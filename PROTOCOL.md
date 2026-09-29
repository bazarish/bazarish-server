# Bazarish gateway protocol

Version 1.

## Scope

The wire protocol between a Bazarish client whose own I2P router is switched off
and a `bazarish-gateway` daemon that runs one for it. It covers the transport,
the authentication, the session, the framing and every operation the client's
transport seam (`RouterBackend`, `EndpointBackend`, `StreamBackend`) has to
answer.

It does not cover the daemon's configuration or deployment, nor what the client
draws on screen.

## What the gateway is

A gateway is a host with an I2P router that a client borrows over the network.
It is a **client-side abstraction**: it is bound to no Bazarish server, it
carries no account, and it keeps nothing once a session has expired. The case it
exists for is a self-hoster running one for himself and the people who already
trust him, and the platform it matters on is mobile, where a full router costs
battery, netDb and tunnels the device would rather not pay for.

It is a third backend beside the embedded engine and SAM, chosen by
`RouterConfig::backend`, and nothing above the transport seam changes.

## Trust

The operator of a gateway sees:

- every destination the client dials, and every address the client publishes,
- which of its own users are talking to each other, since it connects them,
- the keys of every destination the gateway operates, because it mints them,
- the timing and the volume of all of the client's I2P traffic,
- the client's IP address.

The operator does not see: the account identity keys, the profile database, the
message content (end to end encrypted above this layer), or the master key of
the account's serving destination.

Turning the gateway on is therefore an explicit, informed choice, and the one
invariant the protocol keeps is narrow and exact:

> **No key the client owns is ever sent to the gateway, and every destination
> the gateway mints is one-time.**

The client's durable key material is the account identity and the master of its
serving destination. Neither is ever operated locally, so neither has any reason
to travel. Everything the client does operate is minted for a single use and
discarded with it: the facade link, the warm reserve, an outbound lease, a file
transfer and the media destination of a call.

## Transport

| | |
|---|---|
| Transport | TLS 1.3, one WebSocket over it |
| Subprotocol | `Sec-WebSocket-Protocol: bazarish-gateway/1` |
| Frames | Binary only. A text frame closes the socket with 1003 |
| Server authentication | The client pins the SHA-256 of the server's SPKI. The SNI is whatever the client's configuration says, and the gateway accepts any |
| Client authentication | A secret URL **and** a static token in the `X-Bazarish-Gateway` header. Both, or nothing |
| Session | The cookie of a session to rejoin, in `X-Bazarish-Session`. Absent on a first connection |
| Keepalive | The gateway pings every `kKeepalive`; no pong within `kPongTimeout` drops the socket |

### Getting in, and not getting in

The gateway lives at a path nobody guesses and answers only requests carrying
the token. Anything else - the wrong path, the right path with no token, the
right path with the wrong token - gets the same 404 as everything else on the
host, produced by the same handler in the same time. That last part is the whole
point: a 404 that arrives faster, or later, or a byte shorter when the path
happens to be right is an oracle, and an oracle turns a secret path into a
search. The token is compared in constant time and the answer does not depend on
how far the request got.

**The gateway is answerable for this on its own.** It emits one 404, from one
template, in one time, for every way a request can fail to be a request for it,
and it does not rely on anything in front of it to have refused first. A daemon
whose safety depends on somebody else's configuration being right is a daemon
that is unsafe by default, and configurations are edited by people in a hurry.

Checking the token at the front as well - nginx, Caddy - is a good idea and is
recommended to operators: it keeps unauthorised requests off the daemon
entirely, and it makes every 404 on the host come from one server. It is a
recommendation and not a mechanism, and the gateway behaves the same whether or
not anyone took it.

Everything that is not the gateway is the **operator's front**, and it can be
whatever they like - a real site, a holding page, a `proxy_pass` to somebody
else's site entirely. The gateway occupies one unguessable path on a host that
is otherwise honestly whatever it claims to be, and that is a far better story
than a host serving nothing at all.

The pin makes the TLS certificate an identity rather than a trust chain, so the
gateway needs no CA-issued certificate and no real hostname.

## Sessions

A socket is not a session. A session is what holds the destinations, and it
outlives the socket that opened it, because the connection this protocol was
written for is a phone's.

- The static secret authorises. On a successful upgrade with no cookie, the
  gateway creates a session and hands back a fresh **cookie** of
  `kSessionCookieBytes` random bytes in the `ready` frame.
- The client presents that cookie on every reconnect, **together with the
  static secret**: the cookie names a session, it does not authorise one. A
  cookie alone opens nothing.
- While a socket is attached, the session does not expire. When the socket
  drops, the session lives `kSessionTtl` longer, and a reconnect within
  that window rejoins it with every destination and stream still standing.
- A session that expires takes its destinations and streams with it, and its
  cookie stops naming anything. The next connection gets a new session and a new
  cookie, and the client treats it as a router that restarted.
- A cookie presented for a session that does not exist is not an error: the
  gateway opens a fresh session and says `"resumed": false`. The client then
  knows, in one field, that everything it had is gone.
- A second **main** socket presenting a live session's cookie replaces the one
  there, which is closed. A socket that has not noticed it is dead must not be
  able to hold a phone out of its own session. Flow sockets are additions, not
  replacements.
- The cookie lives in memory only. It is a credential with a five minute life,
  and a credential like that has no business in a file.
- A client that stops its router stops its destinations first, and drops the
  cookie: the term a session gets is for a connection that broke, not for
  somebody who has just turned I2P off and would not expect his addresses to
  stay published and reachable for five minutes more.

## Sockets

A session has one **main** socket and a socket of its own for every heavy flow:
each call's media, and each file being sent or received. A client in a call
while two files move holds four.

| Socket | Carries |
|---|---|
| main | The handshake, every control frame, and the data of any stream that has no socket of its own |
| a flow socket | One destination's traffic: a realtime endpoint's datagrams, or every stream on a destination raised for a single transfer |

A WebSocket message cannot be interleaved with another, and the delay is anyway
not the message but the queue behind it: the file sender keeps 128 KiB
outstanding, which is a fifth of a second on a mobile uplink and a full second
on a poor one. No frame size fixes that. A socket of its own gives a flow its
own queue, its own kernel buffer and its own losses, so a call waits for its own
packets, a file waits for its own, and neither waits for the other. Two files no
longer share a window either: the link splits between two TCP flows the way the
network means it to, rather than between two streams inside one.

### Attaching

A flow socket upgrades with the same secret and the same cookie, and its first
frame is `attach` naming the flow: the endpoint id of a realtime destination, or
the id of a stream. There is no second handshake and no second session. A socket
that opens with `hello` is the main one; a socket that opens with `attach` is a
flow's.

`attach` carries how many payload bytes the client has received on that stream,
and the gateway answers `ok` with its own count, which is the same exchange a
resumed session makes and makes migration lossless whenever it happens. A
realtime endpoint has no counts: datagrams are not replayed.

A flow is attached **when it is created** and not afterwards. What is attached
is the **destination**, not the stream: a client raises a destination of its own
for each file it sends or fetches, so the code that creates it knows what it is
for, and a socket taken at that moment has nothing in flight to reorder.
Everything on that destination then rides it.

A stream on a shared destination - a facade link, a lookup - stays on the main
socket. Those are a request and an answer, and a connection each would be a
connection for nothing.

 The counts make a
move lossless; they do not make it ordered. Frames already queued on the socket
being left arrive behind frames on the one being joined, and for a stream that
is a corrupted transfer rather than a slow one. Ordering a live move would need
a sequence number this wire does not carry, and carrying one to serve a case
nobody has measured is not a trade worth making yet. A realtime endpoint takes
its socket at creation, before there is anything to reorder; a stream stays
where it started. What `attach` is for, then, is a socket that died and is being
replaced - where there is nothing in flight on the old one because there is no
old one.

### Losing one

- **A stream** whose socket drops falls back to the main socket until the client
  attaches a new one. A transfer slowed by sharing a queue is better than a
  transfer stopped.
- **A realtime endpoint** whose socket drops has its datagrams dropped until the
  client attaches a new one. Audio that arrives late has already been played
  past, and putting it behind a file to arrive later still helps nobody. The
  client attaches one again by itself, without being asked and without being
  told the lane went: it owes itself a lane for every destination that asked for
  one, whether the lane died or never opened, and a lane nobody takes again is a
  call that is silent for the rest of its life.
- **The main socket** dropping costs the session nothing while a flow socket is
  still up: the session lives while **any** socket is attached, and the five
  minutes begin when the last one drops.

A client may hold `kMaxSocketsPerSession` at once; beyond that the gateway
answers `refused` - and the destination that was refused a lane keeps asking for
one, so it gets its own queue as soon as there is room. It keeps two of them back
for control: the socket it has, and the one that replaces it before the gateway
has noticed the first go. A session filled to the limit could not be handed a new
control socket at all. A data frame for a flow that is not attached to the socket it
arrived on is refused with `wrong-lane` rather than quietly carried: a lane that
works by accident is one that stops working under load, which is exactly when it
was supposed to matter.

### What this costs

Every flow socket is a TLS handshake before its first byte, so the gateway
offers session tickets and the client reuses them; without that a file transfer
pays a full handshake to start. And a fresh connection starts in slow start,
which for a transfer over I2P is hidden behind the tunnels but for one
short-circuited inside the gateway is the first thing the sender feels.

There is also something to give up. One connection hid how many things a client
was doing at once; a connection per flow counts them for anyone watching the
clearnet leg, and the moment each one opens and closes says when a call started
and when a transfer did. The traffic pattern told most of that already - fifty
small packets a second is a call and nothing else looks like it - so what is
lost is the last of a thin cover, not a real one. It is still a loss, and it is
the price of the queue.

On the main socket the writer keeps one frame outstanding and sends control
frames before the data of any stream still riding it.

## Cover

Everything above is encrypted, so an observer of the clearnet leg sees only
three things: how long a connection lives, how many bytes go each way and when,
and how many connections there are. One WebSocket carrying a trickle of small
messages for six hours is not what a browser does, and that shape is the whole
of what a watcher needs.

Two things are done about it, and both are in version 1.

### Decoy requests

On a timer the client sends a decoy to the gateway: an ordinary request to the
same secret URL, carrying the same token, with a body of random bytes. The
gateway answers with random bytes of its own and the client throws them away.
The next one follows after a delay drawn between `kDecoyMinDelay` and
`kDecoyMaxDelay`.

Random in, random out. **The client does not say how much comes back**: the
length of the answer is drawn by the gateway between `kDecoyMinBytes` and
`kDecoyMaxBytes`, and a client that could ask for a size would be a client whose
own behaviour decides what the host's traffic looks like. It is the gateway that
has to resemble a host, so it is the gateway that chooses. The request's own
length is drawn between `kDecoyRequestMinBytes` and `kDecoyRequestMaxBytes`,
which keeps it the shape of a request rather than an upload.

A decoy without the token, or off the secret URL, is a 404 like everything else,
so the gateway is not a source of random bytes for whoever finds it.

Both distributions are the operator's to set, and setting them to resemble what
the front serves is what makes the two populations of traffic to one host look
like one population.

### A control socket that does not live long

The control socket is closed and opened again on purpose. Its life is drawn
between `kControlSocketMinLife` and `kControlSocketMaxLife`, and after it closes
the client waits up to `kControlGapMax` before opening the next one. A socket is
not dropped while it is carrying anything: the draw is taken at the next quiet
moment instead.

What the observer stops seeing is one connection that lives for hours. What they
see instead is a host being fetched from, at intervals, the way a host is
fetched from.

This rides the machinery that is already there for a phone: the reconnect is an
ordinary rejoin by cookie, and the session outliving its socket is what makes a
deliberate disconnect cost nothing. It is worth saying which way round this
works - the gateway holds the long-lived things, the client's leg is
intermittent. The held-open request that waits for mail is an I2P stream on the
gateway, and it stays held while the client has no socket at all; what arrives
in the gap waits in the stream's window and is delivered on the next attach.

The price is stated plainly: `kControlGapMax` is the longest a message can sit
at the gateway before the client hears about it, and it is two seconds because
a break the user can feel is a break not worth taking. That is the trade, and it
is the operator's to set - all five figures, the two decoy delays and the three
that pace the socket, are settings with the protocol's own numbers as their
default.

What a replacement must not cost is a byte. A stream riding the control socket
is put back by the resume exchange: the gateway names what it received, the
client names what it received, and each resends what the other has not
confirmed. Data frames written into the gap are **not** queued for the next
socket - their bytes are still held against their window, and the replay puts
them back in order. Queueing them as well would send them twice, once behind the
replay.

During a call none of this hides much, because a flow socket is up for the
length of the call and fifty small packets a second is a call. Cover is for the
hours a client is idle, which is almost all of them.

## Framing

One WebSocket message carries exactly one frame.

```
+--------+----------+------------------+
| type   | ref      | body             |
| u8     | u32 BE   | type specific    |
+--------+----------+------------------+
```

The body of a control frame is JSON (the library is already a dependency of
`common`). The body of a data frame is the bytes themselves: base64 over a
16 KiB chunk of a file would be a third of the connection spent on nothing.

A frame longer than `kMaxFrameBytes` is a protocol violation and closes the
socket. The cap is not only a memory bound: one connection carries a bulk
transfer and a call's media at the same time, and the cap is how long a media
datagram can be made to wait behind somebody else's file.

### Identifiers

There is **one identifier space** for the whole session, shared by requests,
endpoints and streams. The client allocates even values, the gateway allocates
odd ones (which it does only for an inbound stream). An identifier is never
reused, and it survives a reconnect along with the session, so a frame that
arrives after its subject is gone is recognisably stale rather than ambiguously
fresh. When the counter would wrap, the side that exhausted it ends the session.

`ref` is therefore globally unique, and every response echoes the `ref` of what
it answers.

### Frame types

| Type | Name | From | `ref` | Body |
|---|---|---|---|---|
| 0x01 | `hello` | client | request | `{"version": 1}` |
| 0x02 | `ready` | gateway | echo | the session, below |
| 0x03 | `ok` | gateway | echo | `{}`, or the operation's answer |
| 0x04 | `error` | gateway | echo | `{"code": "...", "message": "..."}` |
| 0x05 | `resume` | client | echo | `{"streams": [{"id": n, "received": n}]}` |
| 0x06 | `attach` | client | flow | `{"received": n}`, on a flow socket's first frame |
| 0x10 | `endpoint-create` | client | endpoint | `{"kind": "stream\|raw", "privacy": "minimal\|middle\|max", "tunnels": 3, "published": true, "realtime": false}` |
| 0x11 | `endpoint-stop` | client | endpoint | `{}` |
| 0x12 | `endpoint-status` | gateway | endpoint | `{"ready": true, "host": "<b33>.b32.i2p", "tunnelsIn": 3, "tunnelsOut": 3, "leaseSets": 2}` |
| 0x20 | `stream-open` | client | stream | `{"endpoint": n, "host": "...", "deadline": 60}` |
| 0x21 | `stream-opened` | gateway | stream | `{}` |
| 0x22 | `stream-inbound` | gateway | stream | `{"endpoint": n, "peer": "<base64>"}` |
| 0x23 | `stream-data` | both | stream | the bytes |
| 0x24 | `stream-credit` | both | stream | u64 BE, the total consumed so far |
| 0x25 | `stream-close` | both | stream | empty |
| 0x26 | `stream-reset` | both | stream | `{"code": "..."}` |
| 0x30 | `raw-send` | client | endpoint | u16 BE host length, host, payload |
| 0x31 | `raw-recv` | gateway | endpoint | payload |

An unknown type closes the socket: a gateway that ignores what it does not
understand is a gateway that silently does half of what was asked.

## Opening and rejoining

The client sends `hello` as its first frame. The gateway answers `ready`:

```json
{
  "version": 1,
  "i2pd": "2.61.0",
  "capabilities": { "routerCounters": false, "destinationCounters": true,
                    "netDbSample": false, "proxy": false, "offlineKeys": false },
  "session": "<cookie>",
  "resumed": true,
  "endpoints": [ { "id": 2, "kind": "stream", "ready": true,
                   "host": "<b33>.b32.i2p", "tunnelsIn": 3, "tunnelsOut": 3,
                   "leaseSets": 2 } ],
  "streams":   [ { "id": 4, "endpoint": 2, "received": 81920, "finished": false } ]
}
```

On a fresh session `resumed` is false and both lists are empty. A version the
gateway does not speak gets `error` with code `version` and a close; there is no
negotiation, because there is one version.

`endpoints` and `streams` are what is still standing, and that is the whole
statement: a destination or a stream the list does not name is gone, whether the
session was rejoined without it or is a new session that never held it. The
client resets those locally on every attach, and needs no separate account of
what died - one would say the same thing twice and could disagree. Each stream
reports how many payload bytes the **gateway** has received on it. The client
answers `resume` with the same count for its own direction, and then both sides:

- drop from their retained buffer everything the peer has confirmed,
- resend what is beyond it, in order, before any new data on that stream,
- recompute the credit window from the confirmed count,
- say again, for every live stream, how much they have consumed of it.

Nothing more is needed to make a reconnect lossless, and nothing less is enough:
a socket dies with bytes in flight, and a stream that quietly loses those bytes
is a corrupted file or a truncated response. The retained buffer costs no extra
memory, because the credit window already bounds what may be in flight to
`kStreamWindowBytes` per stream per direction.

`finished` is the other half of it, and a byte count alone does not carry it: a
`stream-close` lost with the socket would leave a sender waiting for bytes that
are never coming and a reader waiting for an end that already happened. Each
side reports whether it has finished sending, along with how much it has
received.

Datagrams are not replayed. They are best effort by construction, and what was
in flight when the socket died is simply lost. Nothing is held for an endpoint
whose lane is away either: a datagram that arrives while there is nowhere to put
it is dropped, because audio kept back and delivered late has been played past
already. `kDatagramQueue` bounds what the receiving client holds for a reader
that has not come for it yet, oldest dropped.

### Why counts and not acknowledgements

Each side reports one cumulative number per stream per direction, and that is
the whole of the durability mechanism. Numbering every frame and acknowledging
each would be more machinery for less:

- Under a flow is one TCP socket, which does not reorder and does not lose in
  the middle. The only way a stream loses anything is a **truncation** when the
  socket dies, and a truncation is exactly what one cumulative number repairs.
  Sequence numbers and selective acknowledgement solve reordering and holes,
  neither of which can happen here.
- The number is already on the wire. `stream-credit` says how many bytes have
  left the receiver's hands, which is the same count the resume exchange asks
  for, so flow control and durability are one mechanism instead of two that can
  disagree.
- It is idempotent and stateless. Reattaching twice, or reattaching after having
  already resent, converges on the same place; an acknowledgement scheme has a
  retransmit queue keyed by sequence and a dedup table at the far end, both of
  which have to be got right for a case that does not arise.
- Steady state costs nothing: no acknowledgement frames, no timers.

What a byte count does not cover is anything that is not a byte stream, and with
a control socket that is deliberately short-lived there are two such things.

**Requests the client sent and never saw answered.** The client re-sends them on
the next control socket with **the same `ref`**. Identifiers are never reused
inside a session, so a `ref` is an idempotency key that costs nothing to have:
the gateway keeps what it answered for the session's life, and a repeat gets the
recorded answer rather than a second endpoint.

A dial is the case where there is no answer to record yet: it may hold a minute
of deadline, and a socket can die under it. A repeat that names a dial still
running is not answered twice and does not start a second one - it is dropped,
and the dial that is already running answers once, on whatever socket the
session has by then. Two dials behind one identifier would be two streams
wearing it, which is two sets of bytes arriving as one.

**Everything the gateway pushes** needs no replay at all, because `ready`
carries the whole picture: the endpoints that exist and the streams that exist.
A snapshot on every attach supersedes any sequence of pushes that
might have been missed, which is why `endpoint-status` and `stream-inbound` need
no numbering of their own. This is the reason the resume state is a list and not
a log.

## Destinations

**The gateway mints the keys.** `endpoint-create` carries no key material at
all: it says what the destination is for and how it should be built, and the
gateway answers `ok` with the address it created.

```
client -> endpoint-create  ref=2  {"kind": "raw", "privacy": "minimal",
                                   "tunnels": 3, "published": true,
                                   "realtime": true}
gateway -> ok              ref=2  {"host": "<b33>.b32.i2p", "kind": "raw"}
```

The address is the routing host, the blinded b33 form this project publishes,
and it is the only form the client asks for: no client site wants the
destination's base64, only the host it gives a peer.

`kind` is exclusive and there are two:

| `kind` | What it is | Who uses it |
|---|---|---|
| `stream` | TCP-like streams, dialled and accepted | The facade link, the warm reserve, an outbound lease, both ends of a file transfer |
| `raw` | Raw, non-repliable datagrams, no per-packet sender identity | A call's media, and nothing else |

Repliable datagrams are not in version 1. Nothing in the client sends or
receives one, and a kind that no caller has is a kind that cannot be tested.

On the client's side of the seam this is `EndpointConfig::traffic`, said by
whoever raises the destination. It is not read off `realtime`: that names the
lane a destination belongs on, which is a different question from what rides it,
and the two coinciding in one client today is not a reason to make one speak for
the other.

`endpoint-create` deliberately does **not** carry a label or an owner. Those
name what a destination is for and whose it is; they exist for a status view on
the client's own screen, the gateway has no use for them, and a gateway that is
told which destination carries a call and which carries a file learns something
it was not given. `realtime` does travel, because it selects the lane the
gateway pins the destination to, which is the difference between a call that
stutters behind a file transfer and one that does not.

The gateway pushes `endpoint-status` whenever readiness, the tunnel counts or
the held LeaseSets change, and the client answers `ready()` and `waitReady()`
out of what it was last told. `retagEndpoint` is local to the client and sends nothing.

`endpoint-stop` gives up on everything the destination is waiting for and
refuses to start anything new; the gateway resets every stream on it. A stopped
endpoint is finished with, and its identifier is not reused.

### What this costs the client's seam

`EndpointConfig` carries `Keys` today, and under a gateway there are none to
carry. The keys become optional - absent means "the transport mints this" - and
the six places in the client that create a destination stop minting one first.
They are all one-time destinations and none of them looks at the key
afterwards, so nothing else moves.

On this backend `Router::generateKeys()`, `Endpoint::privateBlob()` and
`Endpoint::publicBase64()` throw. That is not a gap to be papered over with an
empty string: a caller that wants the private key of a destination it does not
hold is a caller that is about to be wrong about something.

## Streams

`stream-open` carries the caller's whole deadline, not a per-attempt timeout.
The gateway re-issues the dial every `kDialRetryDelay` until that deadline, and
only a failure that is not "unreachable" is terminal. This is the SAM backend's
lesson, learned against a live router and not against a fake: a LeaseSet that is
not in the netDb yet is a reason to try again, not a reason to fail.

The dial ends in `stream-opened`, or in `stream-reset` with `unreachable`,
`timeout` or `refused`. A dial in flight when the socket drops keeps going: the
deadline belongs to the session, not to the connection, and its answer goes out
on the socket the session has when it is ready rather than the one that asked.

An endpoint created with `published: true` accepts callers. The gateway pushes
`stream-inbound` with an odd identifier of its own as soon as a peer connects,
and the stream is live from that moment; the client's `accept()` hands out what
it has been pushed. The push waits for a control socket if there is none at that
moment - the client replaces its own on purpose, and a caller nobody is told
about is a caller whose far side waits out its deadline for nothing. A client holding more than `kInboundQueue` unaccepted
streams on one endpoint resets the oldest.

### Flow control

Each stream carries a window of `kStreamWindowBytes` in each direction, granted
when it opens. A sender may have at most a window of uncredited bytes in flight,
and retains them until they are credited, which is also what makes a reconnect
lossless. A receiver sends `stream-credit` as bytes leave its hands: for the
gateway, as the I2P stream takes them; for the client, as the application reads
them. Overrunning the window closes the socket.

A credit is **cumulative** - the total consumed so far, not an increment - which
is what makes it the same number the resume exchange asks for and what makes a
credit lost with a socket cost almost nothing: the next one says the same thing
with more of it. It is eight bytes, because nothing promises a file stays under
four gigabytes.

Almost, because there is a case with no next one. A sender whose window is full
sends nothing; nothing moves at the other end, so nothing credits it again; and
the credit that would have opened the window went with the socket. The transfer
is then finished as far as the wire is concerned while a window of it sits in a
queue. So **both sides say their counts again on a socket that has just been
handed over**: a cumulative credit per live stream, which is idempotent by
construction and costs one frame each.

A `stream-close` and a `stream-reset` ride the stream's own socket with its
data, not the main one. Sent on the main socket they would overtake bytes still
queued on the flow's, and a reader would be told the stream had ended before it
had.

The window is what makes `pendingBytes()` answerable at all, and it means the
same thing it always did: bytes handed over that have not left this device yet,
which is written minus credited.

`setReadTimeout` sends nothing: it governs how long the client waits on its own
buffer.

`stream-close` means the sender has no more data; the identifier is retired when
both sides have closed. A `readSome` of a stream whose far side closed returns 0,
as it always did.

## Datagrams

Raw datagrams are best effort, exactly as the router treats them. The gateway
drops a payload the router would drop and says nothing, and so is a datagram
for an endpoint whose socket is not attached. The client keeps at most
`kDatagramQueue` received datagrams per endpoint and drops the oldest, which is
what the embedded path already does. A raw datagram carries no sender identity,
so `raw-recv` carries none either.

Media has a socket to itself, so none of what a file transfer queues stands
between a 20 ms Opus frame and the wire. What is left is what the lane cannot
fix, and it should be written down rather than discovered later.

A media packet on this leg travels over TCP, and TCP will retransmit it until it
arrives. The embedded path sends the same packet as a RAW I2P datagram, where a
loss is simply a loss and Opus conceals it in the 20 ms it owns. Here a lost
packet is resent, arrives after the jitter buffer has played past it, is
discarded, and holds up the packets behind it while it is being fetched. The
lane keeps somebody else's file out of that queue; it does not make the queue
unnecessary.

Removing it needs a datagram leg - QUIC or DTLS between the client and the
gateway - and that is not in version 1. Nothing has been measured: what settles
whether it is worth building is a call over the lane, with its one-way delay and
jitter measured against the same call on a device running its own router.

## Meeting on the gateway

A gateway is a node its users chose to trust with everything, and it sees both
ends of a dial when both ends are its own. When the host named in `stream-open`
or `raw-send` is the routing host of a **published** endpoint this gateway
operates, for any of its sessions, it connects the two directly and nothing
goes out over I2P.

Both kinds are joined this way. A call's datagrams are handed straight across; a
stream becomes a pair of halves inside the gateway, each with the window its own
client granted. Bytes from one side wait in the other's queue until that side's
window has room, and only what has actually left is credited back - crediting a
queue would be telling a sender its bytes had gone when they had only moved.

The point is the call. Two friends on one gateway currently send audio out
through their own tunnels, across the network and back in through the other's,
paying a round trip and a share of every tunnel's loss to reach a destination
that is in the same process. Connecting them directly costs the media nothing
but the gateway's own loop, and a file between them moves at the speed of the
machine rather than of a pair of tunnels.

The rules are narrow:

- **Only published endpoints match.** An unpublished destination is unreachable
  by design and dialling one fails everywhere else; a gateway that made it
  reachable would be a gateway on which the same client code behaves
  differently.
- A directly connected stream reaches the other session as any other inbound
  stream, with `peer` set to the caller's public destination, which the gateway
  knows because it minted it.
- Nothing announces which way a connection went. The client cannot act on the
  difference, and a transport that behaves differently depending on who is
  listening is one with two behaviours to test instead of one.
- The destination is still built and still published. The gateway cannot know
  who will dial an address before the address exists, so the shortcut saves the
  transit, not the setup.

What this reveals, stated plainly: two peers can tell from the timing that they
are on the same gateway. That is new information about each other, not about the
operator, who already sees both of them and every address either one dials. An
operator whose users should not learn this can switch the shortcut off.

The servers refuse exactly this shortcut and must keep refusing it: mail
federates over I2P even between two accounts on one host, because a bypass there
would tell a server operator's users which of them share a server, and a server
is not a node its users picked. A gateway is. The two decisions look opposite
and rest on the same question, which is whether the node in the middle was
chosen.

## What the gateway can answer

| Capability | Under a gateway | Why |
|---|---|---|
| `routerCounters` | false | Routers known, floodfills, tunnels, transport peers: they are the gateway's router's, and that router is shared by everyone using it. A client does not show them, so it is not told them |
| `destinationCounters` | true | Tunnels and held LeaseSets per destination, pushed with `endpoint-status`, for the endpoints of this session and no others |
| `netDbSample` | false | A slice of the netDb is what a server packs into a private reseed. A client never asks for one |
| `proxy` | false | The gateway's clearnet side is its operator's configuration, not a client's |
| `offlineKeys` | false | `refreshOfflineSignature` throws. No client destination is offline-keyed: the one that is belongs to the server and is never operated here |

## The status panel

A session's destinations appear in the I2P status panel exactly as they do when
the router is the one in the process: every one-time destination by name, the
warm reserve among them, with its host, its state and its counts. Running on a
gateway changes where the tunnels are, not what the user is shown.

This needs almost nothing from the protocol, because the panel is already fed
from two places and only one of them is the engine. What a client runs is the
client's own bookkeeping - the SAM backend answers `localDestinations()` from a
registry of its own endpoints and zeroes the counts it cannot know - and the
gateway backend keeps the same registry:

| Field | Where it comes from |
|---|---|
| `label`, `owner` | The client's own `EndpointConfig`, never sent to the gateway |
| `host` | The address `endpoint-create` answered with |
| `published` | What the client asked for |
| `closing` | The client stopped it and is waiting for it to go |
| `ready`, `inboundTunnels`, `outboundTunnels`, `remoteLeaseSets` | The last `endpoint-status`, which is why `destinationCounters` is true here and false under SAM |

So the warm reserve reads "Warm reserve", a call's media destination reads
"Call media", and a destination still building its tunnels reads "building" -
the same words, from the same place, as on a desktop running its own engine.

`localDestinations()` returns this session's endpoints and nothing else. A
gateway serves several clients and each one sees its own, which is not a filter
applied for politeness: the endpoints of another session are not in this
session's registry to begin with, and the gateway is never asked for a list.

After a reconnect the client joins its registry to the `endpoints` list of
`ready` by identifier, and drops every destination that list does not name. The
panel then shows what actually survived, rather than what the client last
remembered.

### What is not shown

The panel's other half, for a router in this process, is the router itself:
routers known, floodfills, tunnels, transport peers. None of it appears under a
gateway and none of it is sent. Those numbers describe the gateway's machine and
everyone else using it, not this account, and a panel that showed them would be
telling a device that runs no router that it knows four thousand of them.

In their place the panel says where the router is - the host, without the path
that opens it - and nothing more. There is no state here to put a light on: the
destinations below carry their own.

The proxy row is absent for the same reason, and the netDb count the panel reads
off the disk while a router is stopped is an embedded-only fact: there is no
local netDb under a gateway, and a count left from an earlier run would be a
number about nothing.

## The health report

`GET <base path>/healthz` answers the fleet's health report and what this
gateway is holding: sessions, destinations, streams, sockets, rejoins and
refusals. It takes the token like everything else at that path, and on top of
it a signature from a fingerprint the operator listed - the token says the
request may reach the gateway, the signature says who is asking.

It is not on a socket of its own, as the other services put theirs. A well-known
`/healthz` on the public address would tell a scan that this host runs a
gateway, which is the one thing the secret path is for.

## Errors

| Code | Meaning |
|---|---|
| `version` | The protocol version is not spoken here |
| `bad-frame` | Malformed, oversized, or a type that does not exist |
| `unknown-id` | The `ref` names nothing, or names something retired |
| `no-endpoint` | The operation names an endpoint that is not on this session |
| `wrong-lane` | A data frame arrived on a socket its flow is not attached to |
| `unsupported` | The operation has no meaning on this transport |
| `refused` | The gateway's own policy refused it |
| `unreachable` | The destination could not be reached before the deadline |
| `timeout` | The deadline ran out |
| `closed` | The stream or endpoint is gone |
| `internal` | The gateway failed at something it was supposed to be able to do |

An operation the gateway cannot perform is an error. It is never a zero, an
empty list or a quiet success: a transport that hides what it did not do is
worse than one that cannot do it.

An end is the exception, and not because it is convenient: a `stream-close` or
`stream-reset` naming a stream the gateway has already retired says exactly what
the gateway already did. The far side ended and the client is saying so a moment
later, or a dial never landed and the client is closing what was never opened.
Both sides agree, so there is nothing to refuse.

## Constants

| Name | Value | Why this value |
|---|---|---|
| `kSessionTtl` | 300 s | How long a session outlives its socket. Long enough for a lift, a tunnel or a handover; short enough that an abandoned phone costs the gateway five minutes of tunnels |
| `kSessionCookieBytes` | 32 | The session cookie, from the system's random source |
| `kMaxFrameBytes` | 16384 | A WebSocket message cannot be interleaved with another, so this is the longest anything can be held by one already going out. It matters most on the main socket, where a stream with no socket of its own shares with control |
| `kMaxSocketsPerSession` | 16 | The main one, a call, and enough transfers that the link is the limit rather than the protocol |
| `kDecoyMinDelay` | 500 ms | The shortest wait between decoy requests |
| `kDecoyMaxDelay` | 300 s | The longest. Past this a host looks abandoned rather than read |
| `kDecoyMinBytes` | 1024 | The smallest decoy answer: a page with nothing on it |
| `kDecoyMaxBytes` | 262144 | The largest: a page with pictures |
| `kDecoyRequestMinBytes` | 256 | The smallest decoy request, which is about what a browser's headers weigh |
| `kDecoyRequestMaxBytes` | 2048 | The largest, past which a request stops looking like one |
| `kControlSocketMinLife` | 1 s | The shortest life of a control socket before it is replaced |
| `kControlSocketMaxLife` | 300 s | The longest. A connection older than this stops looking like a page view |
| `kControlGapMax` | 2 s | The longest wait before the next control socket, and therefore the longest a message can sit at the gateway. The break is the client's own doing and must not be felt; what an observer sees is how many connections there were and how long each lived, not the dead time between them, so a short gap costs the cover nothing |
| `kStreamWindowBytes` | 262144 | The in-flight allowance per stream per direction. It is also the retained buffer a reconnect replays from, and the most an unaccepted inbound stream can cost the gateway |
| `kDialRetryDelay` | 2 s | How often a dial is re-issued while the deadline holds, matching the SAM backend |
| `kInboundQueue` | 8 | Unaccepted inbound streams per endpoint before the client resets the oldest |
| `kDatagramQueue` | 64 | Received datagrams held per endpoint, at either end |
| `kKeepalive` | 30 s | How often the gateway pings |
| `kPongTimeout` | 15 s | A silent peer after a ping is a dead socket |
| `kStatusPeriod` | 250 ms | How often a destination's status is looked at, and pushed when it changed. A fraction of a second because a caller waits for a destination to be ready before it dials, so this is added to every destination that is created |

## What this asks of the client

1. `Backend::eGateway` beside `eEmbedded` and `eSam`, and `RouterConfig` gains
   the gateway's secret URL, its SPKI pin, its SNI and its token.
2. `generateKeys()` on this backend mints locally and the transport does not
   use it: the gateway mints the destination's own and never sends it. The key
   is minted because every caller mints before it creates, and it costs one
   keygen. `privateBlob()` and `publicBase64()` throw rather than answer with
   something empty, which is where an assumption that the address came from
   those keys is caught.
3. `common/src/I2pGateway.cpp`: `RouterBackend`, `EndpointBackend` and
   `StreamBackend` over the session's sockets, built by `makeGatewayRouter`. It
   attaches a socket to every realtime endpoint and every file transfer, reuses
   TLS tickets, and sends control before unattached stream data on the main one.
4. `setSocksProxy` is called unconditionally when the client builds its router;
   it has to ask `capabilities().proxy` first.
5. A decoy timer, and a control socket the client replaces on purpose. Both are
   the client's own business: the gateway only answers.
6. The status view distinguishes two backends today and will have to
   distinguish three: it names the gateway beside the router numbers, drops the
   proxy row, and stops reading the on-disk netDb count, which means nothing
   when there is no local netDb.

## What is not built yet

Written down rather than discovered later.

- **Nothing has run against a live I2P network.** The daemon, the wire and the
  transport are proved end to end against each other - a destination the gateway
  minted and named, two of its own clients meeting inside it, and a transfer
  carried across nine replacements of the socket under it. What is untested is a
  tunnel actually carrying something.
7. One global setting switches the router off. The library stays linked, because
   the account's own destination is still minted on the device.
