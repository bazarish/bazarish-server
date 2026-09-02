// Bazarish project (c) 2026
// The operator panel. Everything past the sign-in page is drawn here from the
// panel's JSON API; the panel itself holds no user state, it passes the calls
// through to the services that own it.
(function () {
    "use strict";

    // How often the monitoring view re-probes the fleet.
    var kHealthPollMs = 5000;
    // How long to wait after the last keystroke before searching, so a typed
    // fingerprint is one request rather than fifty-two.
    var kSearchDebounceMs = 250;
    // Accounts fetched per request; the next page loads as the list is scrolled.
    var kPageSize = 25;
    var kBytesPerMiB = 1024 * 1024;
    // A quota an operator can enter, in whole megabytes.
    var kMinQuotaMiB = 1;
    var kMaxQuotaMiB = 1024 * 1024;
    var kSecondsPerMs = 1000;
    // What a login challenge may carry, matching the node's own caps: display
    // limits, so the badge a user reads shows the whole of every field.
    var kConsumerNameMax = 96;
    var kConsumerPlaceMax = 256;
    var kConsumerRoleMax = 48;
    // A hold is the soft measure - the operator is stopping the account in order
    // to say something - so the field starts with the plainest version of it.
    var kDefaultHoldMessage = "Service for this account has been stopped.";

    var content = document.getElementById("content");
    // The deployment the account views act on. Monitoring shows every one of
    // them; Users and Settings always act on one, because a quota belongs to a
    // server and not to a screen.
    var fleet = window.localStorage.getItem("bazarish.fleet") || "";
    var nav = document.getElementById("nav");
    var pollTimer = null;

    // A service answers a failure as {"error": {"code", "message"}}; the panel
    // answers with {"error": "text"}. Either way the operator gets a sentence,
    // not an object rendered as one.
    function errorText(data, status) {
        var error = data && data.error;
        if (typeof error === "string" && error) {
            return error;
        }
        if (error && typeof error.message === "string" && error.message) {
            return error.code ? error.message + " (" + error.code + ")" : error.message;
        }
        return "HTTP " + status;
    }

    // Every account call names the deployment it is about.
    function withFleet(path) {
        if (!fleet) {
            return path;
        }
        return path + (path.indexOf("?") >= 0 ? "&" : "?") + "fleet=" + encodeURIComponent(fleet);
    }

    function api(method, path, body) {
        return fetch(path, {
            method: method,
            headers: body ? { "Content-Type": "application/json" } : {},
            body: body ? JSON.stringify(body) : undefined,
            credentials: "same-origin"
        }).then(function (response) {
            if (response.status === 401) {
                window.location.href = "/login";
                throw new Error("signed out");
            }
            return response.json().catch(function () {
                throw new Error("HTTP " + response.status);
            }).then(function (data) {
                if (!response.ok) {
                    throw new Error(errorText(data, response.status));
                }
                return data;
            });
        });
    }

    function element(tag, className, text) {
        var node = document.createElement(tag);
        if (className) {
            node.className = className;
        }
        if (text !== undefined) {
            node.textContent = text;
        }
        return node;
    }

    // One labelled value, with whatever belongs beside it (a copy mark, say).
    function fact(label, value, beside) {
        var row = element("li");
        row.appendChild(element("span", "fact-label", label));
        var side = element("span", "fact-value");
        side.appendChild(element("b", null, value));
        if (beside) {
            side.appendChild(beside);
        }
        row.appendChild(side);
        return row;
    }

    // What decides which list an address belongs in: the host, not the scheme.
    function isI2pUrl(url) {
        var withoutScheme = url.replace(/^[a-zA-Z]+:\/\//, "");
        var host = withoutScheme.split(/[:/]/)[0];
        return /\.b32\.i2p$/.test(host);
    }

    function humanBytes(bytes) {
        var units = ["B", "KiB", "MiB", "GiB", "TiB"];
        var value = Number(bytes) || 0;
        var unit = 0;
        while (value >= 1024 && unit + 1 < units.length) {
            value /= 1024;
            unit += 1;
        }
        return (value < 10 ? value.toFixed(1) : Math.round(value)) + " " + units[unit];
    }

    function humanDate(unixSeconds) {
        if (!unixSeconds) {
            return "never";
        }
        return new Date(unixSeconds * kSecondsPerMs).toISOString().replace("T", " ").slice(0, 16);
    }

    function notice(message, kind) {
        return element("p", "notice" + (kind ? " " + kind : ""), message);
    }

    function view(title) {
        content.innerHTML = "";
        var box = element("div", "view");
        box.appendChild(element("h1", "view-title", title));
        content.appendChild(box);
        return box;
    }

    // --- monitoring -------------------------------------------------------

    function humanCount(n) {
        const value = Number(n) || 0;
        if (value < 1000) {
            return String(value);
        }
        return value < 1000000 ? (value / 1000).toFixed(1) + "k"
            : (value / 1000000).toFixed(1) + "M";
    }

    function serviceCard(service) {
        var card = element("div", "card");
        var head = element("div", "card-head");
        head.appendChild(element("i", "dot " + (service.up ? "is-up" : "is-down")));
        head.appendChild(element("span", "card-name", service.name));
        head.appendChild(element("span", "tag", service.up ? "up" : "down"));
        card.appendChild(head);

        var facts = element("ul", "facts");
        facts.appendChild(fact("kind", service.kind));
        facts.appendChild(fact("address", service.url));
        if (service.up) {
            facts.appendChild(fact("version", service.version || "-"));
            facts.appendChild(fact("uptime", service.uptime));
            facts.appendChild(fact("memory",
                humanBytes(service.ramBytes) + " / " + humanBytes(service.ramPeakBytes) + " peak"));
            // A facade is the way in, so what it is carrying is the load of the
            // whole deployment as clients see it.
            if (service.kind === "facade") {
                facts.appendChild(fact("requests", humanCount(service.requestsLastMinute)
                    + "/min  " + humanCount(service.requestsLastHour)
                    + "/h  " + humanCount(service.requestsLastDay) + "/day"));
                facts.appendChild(fact("in flight", String(service.inFlight)));
            }
        } else {
            facts.appendChild(fact("error", (service.error || "no answer")
                + (service.status ? " (HTTP " + service.status + ")" : "")));
        }
        facts.appendChild(fact("latency", service.latencyMs + " ms"));
        card.appendChild(facts);
        return card;
    }

    function renderMonitoring() {
        var box = view("monitoring");
        var groups = element("div");
        box.appendChild(groups);

        function load() {
            api("GET", "/api/services").then(function (data) {
                groups.innerHTML = "";
                if (!data.services.length) {
                    groups.appendChild(element("p", "muted", "No services configured."));
                    return;
                }
                // One block per deployment: a server, the node bound to it and
                // the facades in front of the pair.
                data.fleets.forEach(function (name) {
                    var mine = data.services.filter(function (service) {
                        return service.fleet === name;
                    });
                    if (!mine.length) {
                        return;
                    }
                    if (data.fleets.length > 1) {
                        groups.appendChild(element("h2", "block-title", name));
                    }
                    var cards = element("div", "cards");
                    mine.forEach(function (service) {
                        cards.appendChild(serviceCard(service));
                    });
                    groups.appendChild(cards);
                });
            }).catch(function (error) {
                groups.innerHTML = "";
                groups.appendChild(notice(error.message, "is-error"));
            });
        }

        load();
        pollTimer = window.setInterval(load, kHealthPollMs);
    }

    // --- users ------------------------------------------------------------

    function isDelegated(user) {
        return Boolean(user.transientExpires)
            && user.transientExpires * kSecondsPerMs > Date.now();
    }

    function stateTags(user) {
        var tags = element("span", "row-tags");
        if (user.banned) {
            tags.appendChild(element("span", "tag is-banned", "banned"));
            return tags;
        }
        if (user.approval === "pending") {
            tags.appendChild(element("span", "tag is-pending", "pending"));
        } else if (user.approval === "approved") {
            tags.appendChild(element("span", "tag is-approved", "approved"));
        } else {
            tags.appendChild(element("span", "tag", "no account"));
        }
        if (isDelegated(user)) {
            tags.appendChild(element("span", "tag is-live", "delegated"));
        } else if (user.dest) {
            // An address that was published and is no longer operated: the
            // account is reachable at nothing until the client renews.
            tags.appendChild(element("span", "tag is-pending", "lapsed"));
        } else {
            tags.appendChild(element("span", "tag", "no address"));
        }
        return tags;
    }

    // A block of one subject, separated from its neighbours so a card of many
    // controls reads as a few decisions rather than a pile of inputs.
    function section(box, title) {
        var block = element("section", "block");
        if (title) {
            block.appendChild(element("h3", "block-title", title));
        }
        box.appendChild(block);
        return block;
    }

    // One row of controls, then the sentence that says what they do.
    function controls(block, hint) {
        var row = element("div", "controls");
        block.appendChild(row);
        if (hint) {
            block.appendChild(element("p", "hint", hint));
        }
        return row;
    }

    function actionButton(label, kind, run) {
        var button = element("button", "btn " + kind, label);
        button.addEventListener("click", function () {
            button.disabled = true;
            run(function () {
                button.disabled = false;
            });
        });
        return button;
    }

    function userDetail(user, onChanged, onError, onGone) {
        var box = element("div", "detail");

        var head = element("div", "detail-head");
        head.appendChild(element("p", "detail-key", user.user));
        head.appendChild(window.bazarishCopy.icon(function () {
            return user.user;
        }, "Copy the fingerprint"));
        box.appendChild(head);

        var facts = element("ul", "facts");
        facts.appendChild(fact("approval", user.banned ? "banned" : user.approval));
        if (user.banned) {
            facts.appendChild(fact("reason", user.banReason || "-"));
        }
        if (user.holdMessage) {
            facts.appendChild(fact("message", user.holdMessage));
        }
        facts.appendChild(fact("registered", humanDate(user.registeredAt)));
        if (user.approval === "pending") {
            facts.appendChild(fact("waiting since", humanDate(user.requestedAt)));
        }
        if (user.approval === "approved") {
            facts.appendChild(fact("approved", humanDate(user.approvedAt)));
        }
        facts.appendChild(fact("account",
            user.registered ? "registered" : "not redeemed yet"));
        facts.appendChild(fact("address", user.dest || "none published",
            user.dest ? window.bazarishCopy.icon(function () {
                return user.dest;
            }, "Copy the address") : null));
        facts.appendChild(fact("delegation",
            isDelegated(user) ? "until " + humanDate(user.transientExpires)
                : (user.delegatedAt ? "lapsed, last " + humanDate(user.delegatedAt) : "none")));
        // The mailbox and the devices live on the messaging server, so they come
        // in after the row does.
        var mailbox = fact("mailbox", "...");
        var devices = fact("devices", "...");
        facts.appendChild(mailbox);
        facts.appendChild(devices);
        api("GET", withFleet("/api/account?user=" + encodeURIComponent(user.user))).then(function (data) {
            mailbox.lastChild.textContent = humanBytes(data.usedBytes) + " of "
                + humanBytes(data.quotaBytes);
            devices.lastChild.textContent = String(data.devices);
        }).catch(function (error) {
            mailbox.lastChild.textContent = "unknown (" + error.message + ")";
            devices.lastChild.textContent = "unknown";
        });
        // An account lives while it keeps delegating; say when this one runs out
        // if nothing changes, so "idle" has a date attached to it.
        if (user.sweepAt) {
            facts.appendChild(fact("deleted unless it delegates", humanDate(user.sweepAt)));
        }
        box.appendChild(facts);

        if (user.banned) {
            controls(section(box, "Ban"), "The key may register again.")
                .appendChild(actionButton("Lift the ban", "btn-quiet", function (done) {
                    api("POST", withFleet("/api/unban"), { user: user.user }).then(function () {
                        onChanged("Ban lifted.");
                    }).catch(function (error) {
                        done();
                        onError(error);
                    });
                }));
            return box;
        }

        var quotaBlock = section(box, "Storage quota");
        var quotaRow = controls(quotaBlock);
        var quota = element("input", "field quota-input");
        quota.type = "number";
        quota.min = String(kMinQuotaMiB);
        quota.max = String(kMaxQuotaMiB);
        quota.step = "1";
        quota.value = String(Math.max(kMinQuotaMiB, Math.round(user.quotaBytes / kBytesPerMiB)));
        quotaRow.appendChild(quota);
        quotaRow.appendChild(element("span", "unit", "MB"));
        quotaRow.appendChild(actionButton("Save", "btn-quiet", function (done) {
            var megabytes = Number(quota.value);
            if (!Number.isFinite(megabytes) || megabytes < kMinQuotaMiB
                || megabytes > kMaxQuotaMiB) {
                done();
                onError(new Error("A quota is a whole number of megabytes."));
                return;
            }
            api("PUT", withFleet("/api/quota"), {
                user: user.user,
                quotaBytes: Math.round(megabytes) * kBytesPerMiB
            }).then(function () {
                onChanged("Quota set to " + Math.round(megabytes) + " MB.");
            }).catch(function (error) {
                done();
                onError(error);
            });
        }));

        // What the operator can do to an account depends on where it stands. An
        // account already out of service has nothing to take out of it; one that
        // was never redeemed by a client has nothing to approve.
        var onHold = user.approval === "pending" && Boolean(user.holdMessage);
        if (user.approval === "pending") {
            controls(section(box, onHold ? "Back into service" : "Approval"),
                onHold ? "Its client republishes the address within a minute, and the account is"
                    + " served again."
                    : "The account is served from now on.")
                .appendChild(actionButton(onHold ? "Return to service" : "Approve", "",
                    function (done) {
                        api("POST", withFleet("/api/approve"), { user: user.user }).then(function () {
                            onChanged(onHold ? "Back in service." : "Approved.");
                        }).catch(function (error) {
                            done();
                            onError(error);
                        });
                    }));
        }

        if (user.approval === "approved" || onHold) {
            var holdBlock = section(box,
                onHold ? "Message to its owner" : "Take out of service");
            var holdRow = controls(holdBlock, onHold
                ? "The account stays out of service; this replaces what its owner reads."
                : "The soft measure: the address is revoked, the account waits for you again, and"
                    + " its owner reads this line instead of the node-wide one.");
            var holdNote = element("input", "field");
            holdNote.type = "text";
            holdNote.value = onHold ? user.holdMessage : kDefaultHoldMessage;
            holdRow.appendChild(holdNote);
            holdRow.appendChild(actionButton(onHold ? "Update message" : "Undelegate", "btn-quiet",
                function (done) {
                    if (!holdNote.value.trim()) {
                        done();
                        onError(new Error("Say what you are stopping the account for."));
                        return;
                    }
                    api("POST", withFleet("/api/undelegate"), {
                        user: user.user,
                        message: holdNote.value.trim()
                    }).then(function () {
                        onChanged(onHold ? "Message updated." : "Undelegated. The account is on hold.");
                    }).catch(function (error) {
                        done();
                        onError(error);
                    });
                }));
        }

        if (user.approval === "none") {
            section(box, "Approval").appendChild(element("p", "hint",
                "Registered at the portal and not redeemed by a client yet - there is nothing to"
                + " approve or take out of service."));
        }

        var removeBlock = section(box, "Remove");
        controls(removeBlock,
            "Deletes the certificate, the grants and the address. The key may register again.")
            .appendChild(actionButton("Delete account", "btn-danger", function (done) {
                if (!window.confirm("Delete this account? The key may register again.")) {
                    done();
                    return;
                }
                api("POST", withFleet("/api/delete"), { user: user.user }).then(function () {
                    onGone("Account deleted.");
                }).catch(function (error) {
                    done();
                    onError(error);
                });
            }));

        var banRow = controls(removeBlock,
            "The same, and this key does not register here again.");
        var banReason = element("input", "field");
        banReason.type = "text";
        banReason.placeholder = "Reason shown to the key (default: Banned)";
        banRow.appendChild(banReason);
        banRow.appendChild(actionButton("Ban key", "btn-danger", function (done) {
            if (!window.confirm("Ban this key? It will not register here again.")) {
                done();
                return;
            }
            api("POST", withFleet("/api/ban"), {
                user: user.user,
                reason: banReason.value.trim()
            }).then(function () {
                onGone("Key banned.");
            }).catch(function (error) {
                done();
                onError(error);
            });
        }));

        return box;
    }

    function renderUsers(selected) {
        var box = view("users");

        var state = "all";
        // The open account is in the address bar, so an operator can hand a
        // colleague a link to the account they are talking about.
        var openUser = selected || null;
        var offset = 0;
        var total = 0;
        var loading = false;
        var exhausted = false;

        var toolbar = element("div", "toolbar");
        var search = element("input", "field search");
        search.type = "search";
        search.placeholder = "Search by fingerprint or address";
        search.autocomplete = "off";
        toolbar.appendChild(search);

        var chips = {};
        ["all", "pending", "approved"].forEach(function (name) {
            var chip = element("button", "chip" + (name === state ? " is-on" : ""), name);
            chip.addEventListener("click", function () {
                state = name;
                Object.keys(chips).forEach(function (key) {
                    chips[key].className = "chip" + (key === state ? " is-on" : "");
                });
                reload();
            });
            chips[name] = chip;
            toolbar.appendChild(chip);
        });
        box.appendChild(toolbar);

        var flash = element("div", "flash-slot");
        box.appendChild(flash);
        var count = element("p", "muted", "");
        box.appendChild(count);
        var rows = element("div", "rows");
        box.appendChild(rows);
        var more = element("p", "muted more", "");
        box.appendChild(more);

        function say(message, kind) {
            flash.innerHTML = "";
            flash.appendChild(notice(message, kind));
        }

        function reload() {
            offset = 0;
            exhausted = false;
            rows.innerHTML = "";
            loadPage();
        }

        function addRow(user) {
            var row = element("button", "row" + (openUser === user.user ? " is-open" : ""));
            row.type = "button";
            var keys = element("span", "row-keys");
            keys.appendChild(element("span", "row-key", user.user));
            keys.appendChild(element("span", "row-dest", user.dest || "no address published"));
            row.appendChild(keys);
            row.appendChild(stateTags(user));
            row.appendChild(element("span", "row-quota",
                Math.round(user.quotaBytes / kBytesPerMiB) + " MB"));
            row.addEventListener("click", function () {
                openUser = openUser === user.user ? null : user.user;
                setHash(openUser ? "#/users/" + openUser : "#/users");
                reload();
            });
            rows.appendChild(row);
            if (openUser === user.user) {
                rows.appendChild(userDetail(user, function (message) {
                    say(message);
                    reload();
                }, function (error) {
                    say(error.message, "is-error");
                }, function (message) {
                    // The account this card was about is gone: leaving a card
                    // open would put another account's one in its place.
                    openUser = null;
                    setHash("#/users");
                    say(message);
                    reload();
                }));
            }
        }

        function loadPage() {
            if (loading || exhausted) {
                return;
            }
            loading = true;
            more.textContent = "Loading...";
            var query = "/api/users?q=" + encodeURIComponent(search.value.trim())
                + "&state=" + encodeURIComponent(state)
                + "&limit=" + kPageSize + "&offset=" + offset;
            api("GET", withFleet(query)).then(function (data) {
                loading = false;
                total = data.total;
                data.users.forEach(addRow);
                offset += data.users.length;
                exhausted = data.users.length === 0 || offset >= total;
                count.textContent = offset >= total
                    ? total + " account(s)"
                    : "showing " + offset + " of " + total;
                more.textContent = exhausted ? "" : "Scroll for more";
                if (!rows.children.length) {
                    rows.appendChild(element("p", "muted", "Nothing here."));
                }
                // A short page that does not fill the window would never scroll,
                // and the rest would stay unreachable.
                if (!exhausted && more.getBoundingClientRect().top < window.innerHeight) {
                    loadPage();
                }
            }).catch(function (error) {
                loading = false;
                exhausted = true;
                more.textContent = "";
                say(error.message, "is-error");
            });
        }

        window.addEventListener("scroll", onScroll, { passive: true });
        function onScroll() {
            if (!content.contains(rows)) {
                window.removeEventListener("scroll", onScroll);
                return;
            }
            if (more.getBoundingClientRect().top < window.innerHeight) {
                loadPage();
            }
        }

        var debounce = null;
        search.addEventListener("input", function () {
            window.clearTimeout(debounce);
            debounce = window.setTimeout(reload, kSearchDebounceMs);
        });
        reload();
        search.focus();
    }

    // --- settings ---------------------------------------------------------

    // Settings are grouped by what they are about, not by what type they are: an
    // operator looking for "who may sign in" should not have to read past the
    // captcha to find it. One tab is one subject, and each saves on its own.
    var kSettingsTabs = [
        { id: "registration", label: "Registration" },
        { id: "portal", label: "Portal" },
        { id: "addresses", label: "Addresses" },
        { id: "accounts", label: "Accounts" },
        { id: "server", label: "Messaging server" },
        { id: "facade", label: "Facade" },
        { id: "panel", label: "Panel" }
    ];
    var kLogLevels = ["error", "warn", "info", "debug"];
    var kPrivacyLevels = ["minimal", "middle", "max"];
    // How long a restarted service is given before the page asks it again. The
    // unit's own RestartSec is the operator's to set; this is only how long the
    // page waits before it stops saying "restarting".
    var kRestartWaitMs = 10000;
    var settingsTab = kSettingsTabs[0].id;

    // A value the operator types. `hint` explains it; `restart` marks the ones
    // the service only reads when it starts.
    function fieldRow(block, label, value, spec) {
        var options = spec || {};
        var row = controls(block, options.hint);
        row.appendChild(element("span", "control-label", label));
        var input = element("input", "field" + (options.narrow ? " quota-input" : ""));
        input.type = options.type || "text";
        if (options.limit) {
            input.maxLength = options.limit;
        }
        if (options.min !== undefined) {
            input.min = String(options.min);
        }
        if (options.placeholder) {
            input.placeholder = options.placeholder;
        }
        input.value = value === null || value === undefined ? "" : String(value);
        row.appendChild(input);
        if (options.unit) {
            row.appendChild(element("span", "unit", options.unit));
        }
        if (options.restart) {
            row.appendChild(element("span", "badge-restart", "restart"));
        }
        return input;
    }

    // A value the panel knows but cannot change. Deliberately not an input: an
    // operator must be able to tell at a glance what is theirs to edit.
    function readOnlyRow(block, label, value, hint) {
        var row = controls(block, hint);
        row.appendChild(element("span", "control-label", label));
        var shown = value === null || value === undefined || value === "" ? "not set" : String(value);
        row.appendChild(element("span", "readonly" + (shown === "not set" ? " is-unset" : ""), shown));
        return row;
    }

    // A host and a port on one line: they are one address and are edited as one.
    function endpointRow(block, label, endpoint, hint, restart) {
        var value = endpoint || {};
        var row = controls(block, hint);
        row.appendChild(element("span", "control-label", label));
        var host = element("input", "field");
        host.type = "text";
        host.value = value.host || "";
        host.placeholder = "127.0.0.1";
        row.appendChild(host);
        var port = element("input", "field quota-input");
        port.type = "number";
        port.min = "1";
        port.max = "65535";
        port.value = value.port ? String(value.port) : "";
        row.appendChild(port);
        if (restart) {
            row.appendChild(element("span", "badge-restart", "restart"));
        }
        return { host: host, port: port };
    }

    function chipRow(block, hint, choices, current, onPick) {
        var row = controls(block, hint);
        var chips = {};
        var picked = current;
        choices.forEach(function (choice) {
            var chip = element("button", "chip" + (choice.value === picked ? " is-on" : ""),
                choice.label);
            chip.addEventListener("click", function () {
                picked = choice.value;
                Object.keys(chips).forEach(function (key) {
                    chips[key].className = "chip" + (key === String(picked) ? " is-on" : "");
                });
                if (onPick) {
                    onPick(picked);
                }
            });
            chips[String(choice.value)] = chip;
            row.appendChild(chip);
        });
        return function () { return picked; };
    }

    function textareaBlock(block, value, placeholder, hint, tall) {
        var area = element("textarea", "field" + (tall ? " field-tall" : ""));
        area.value = value || "";
        area.placeholder = placeholder;
        controls(block, hint).appendChild(area);
        return area;
    }

    function linesOf(area) {
        return area.value.split("\n").map(function (line) {
            return line.trim();
        }).filter(function (line) {
            return line.length > 0;
        });
    }

    // One button per tab, on a line of its own: nothing above it takes effect
    // until it is pressed, and pressing it saves that tab and nothing else.
    function saveFooter(form, note, gather) {
        var footer = element("div", "form-footer");
        var save = element("button", "btn", "Save");
        footer.appendChild(save);
        footer.appendChild(element("span", "hint", note));
        form.appendChild(footer);
        save.addEventListener("click", function () {
            var call;
            try {
                call = gather();
            } catch (error) {
                footer.appendChild(notice(error.message, "is-error"));
                return;
            }
            if (!call) {
                return;
            }
            save.disabled = true;
            api(call.method, call.path, call.body).then(function () {
                renderSettings();
            }).catch(function (error) {
                save.disabled = false;
                footer.appendChild(notice(error.message, "is-error"));
            });
        });
        return footer;
    }

    // A service is restarted from here because a setting only a start reads is
    // otherwise saved and inert until somebody opens a terminal on the server.
    function restartButton(footer, kind, canRestart) {
        if (!canRestart) {
            footer.appendChild(element("span", "hint",
                "This service cannot restart itself: its unit has no restart policy."));
            return;
        }
        var button = element("button", "chip", "restart " + kind);
        button.addEventListener("click", function () {
            button.disabled = true;
            button.textContent = "restarting " + kind + "...";
            api("POST", withFleet("/api/restart?kind=" + encodeURIComponent(kind)))
                .then(function () {
                    window.setTimeout(renderSettings, kRestartWaitMs);
                })
                .catch(function (error) {
                    button.disabled = false;
                    button.textContent = "restart " + kind;
                    footer.appendChild(notice(error.message, "is-error"));
                });
        });
        footer.appendChild(button);
    }

    function portRead(input, what) {
        var port = Number(input.value);
        if (!Number.isInteger(port) || port < 1 || port > 65535) {
            throw new Error(what + " needs a port between 1 and 65535.");
        }
        return port;
    }

    function renderSettings(wanted) {
        // The tab is in the address, like the open account is: a link points at
        // one subject rather than at "settings, then click around".
        if (wanted && kSettingsTabs.some(function (tab) { return tab.id === wanted; })) {
            settingsTab = wanted;
        }
        setHash("#/settings/" + settingsTab);
        var box = view("settings");
        var bar = element("nav", "tabs");
        kSettingsTabs.forEach(function (tab) {
            var button = element("button", "tab" + (tab.id === settingsTab ? " is-on" : ""),
                tab.label);
            button.addEventListener("click", function () {
                renderSettings(tab.id);
            });
            bar.appendChild(button);
        });
        box.appendChild(bar);

        var form = element("div", "panel-box");
        box.appendChild(form);
        form.appendChild(element("p", "muted", "Loading..."));

        if (settingsTab === "panel") {
            api("GET", "/api/panel").then(function (data) {
                form.innerHTML = "";
                renderPanelTab(form, data);
            }).catch(function (error) {
                form.innerHTML = "";
                form.appendChild(notice(error.message, "is-error"));
            });
            return;
        }

        // The other two services answer for their own configuration; the panel
        // only carries the request to them.
        if (settingsTab === "server" || settingsTab === "facade") {
            var kind = settingsTab === "server" ? "server-core" : "facade";
            api("GET", withFleet("/api/service-settings?kind=" + kind))
                .then(function (data) {
                    form.innerHTML = "";
                    if (kind === "server-core") {
                        renderServerTab(form, data);
                    } else {
                        renderFacadeTab(form, data);
                    }
                }).catch(function (error) {
                    form.innerHTML = "";
                    form.appendChild(notice(error.message, "is-error"));
                });
            return;
        }

        api("GET", withFleet("/api/settings")).then(function (data) {
            form.innerHTML = "";
            if (settingsTab === "registration") {
                renderRegistrationTab(form, data);
            } else if (settingsTab === "portal") {
                renderPortalTab(form, data);
            } else if (settingsTab === "addresses") {
                renderAddressesTab(form, data);
            } else {
                renderAccountsTab(form, data);
            }
        }).catch(function (error) {
            form.innerHTML = "";
            form.appendChild(notice(error.message, "is-error"));
        });
    }

    function renderRegistrationTab(form, data) {
        var how = section(form, "Who gets an account");
        var moderated = chipRow(how,
            "Open: an account is served as soon as it registers. Moderated: it waits for you.",
            [{ value: false, label: "open" }, { value: true, label: "moderated" }],
            Boolean(data.requireApproval));
        var captcha = chipRow(how,
            "Captcha: a person registers on the portal. No captcha: a client registers itself"
            + " the moment it connects, and nobody visits a page.",
            [{ value: true, label: "captcha" }, { value: false, label: "no captcha" }],
            data.requireCaptcha !== false);
        var length = fieldRow(how, "Captcha length", data.captchaLength, {
            type: "number", narrow: true, min: 3, unit: "characters", restart: true,
            hint: "How many characters a person has to read off the image."
        });
        var ttl = fieldRow(how, "Captcha lifetime", data.captchaTtlSeconds, {
            type: "number", narrow: true, min: 60, unit: "seconds", restart: true,
            hint: "How long one captcha stays valid before a new one is drawn."
        });

        var says = section(form, "What people are told");
        var portalMessage = textareaBlock(says, data.portalMessage,
            "What this server is, and what registering here means",
            "Shown by a client that reaches this server without an account here.");
        var waiting = textareaBlock(says, data.registrationMessage, "How to reach you",
            "Shown to an account that is registered but not served yet - in the portal and in"
            + " its client.");

        var footer = saveFooter(form,
            "Applies now and is written to the node's config, so a restart keeps it.",
            function () {
                return {
                    method: "PUT", path: withFleet("/api/settings"),
                    body: {
                        requireApproval: moderated(),
                        requireCaptcha: captcha(),
                        captchaLength: Number(length.value) || 0,
                        captchaTtlSeconds: Number(ttl.value) || 0,
                        portalMessage: portalMessage.value.trim(),
                        registrationMessage: waiting.value.trim()
                    }
                };
            });
        restartButton(footer, "service-node", data.canRestart);
    }

    function renderPortalTab(form, data) {
        var consumer = data.loginConsumer || {};
        var signing = section(form, "What a user sees before signing in");
        var name = fieldRow(signing, "Name", consumer.name, {
            limit: kConsumerNameMax, placeholder: "The name of this site",
            hint: "Shown in the client's window before a user signs a login for this portal."
        });
        var place = fieldRow(signing, "Address", consumer.place, {
            limit: kConsumerPlaceMax, placeholder: "http://host:port",
            hint: "The address a user has in their address bar. They compare the two before"
                + " signing, so write the address they actually opened - if you front this"
                + " portal under another name, that is the one to put here."
        });
        var role = fieldRow(signing, "Role", consumer.role, {
            limit: kConsumerRoleMax, placeholder: "Account owner",
            hint: "What signing in here opens - whose account the signature is for."
        });

        var reach = section(form, "Where the portal answers");
        var links = textareaBlock(reach, (data.portalLinks || []).join("\n"),
            "https://host:port",
            "Links a client shows a person who has no account here yet, one per line.");
        var listen = endpointRow(reach, "Listens on", data.portalListen,
            "The socket the portal binds. Changing it moves the page an operator opens.", true);

        var footer = saveFooter(form,
            "The words apply to the next challenge; the listener needs a restart.",
            function () {
                var signer = {
                    name: name.value.trim(), place: place.value.trim(), role: role.value.trim()
                };
                var missing = Object.keys(signer).filter(function (key) {
                    return signer[key].length === 0;
                });
                if (missing.length > 0) {
                    throw new Error("A portal that will not say its " + missing[0]
                        + " has no business asking anyone to sign for it.");
                }
                return {
                    method: "PUT", path: withFleet("/api/settings"),
                    body: {
                        loginConsumer: signer,
                        portalLinks: linesOf(links),
                        portalListen: {
                            host: listen.host.value.trim(),
                            port: portRead(listen.port, "The portal")
                        }
                    }
                };
            });
        restartButton(footer, "service-node", data.canRestart);
    }

    function renderAddressesTab(form, data) {
        var reach = section(form, "How clients reach this server");
        var facades = textareaBlock(reach, (data.facades || []).join("\n"),
            "http://<b32>.b32.i2p/<base path>",
            "Facades, one per line, in the order a client tries them. Clients talk to this"
            + " server over I2P and nothing else, so every one of these is a .b32.i2p address.",
            true);
        var reseeds = textareaBlock(reach, (data.reseeds || []).join("\n"),
            "https://host:port/<base path>",
            "Reseeds, one per line: clearnet addresses where a client with no I2P router yet"
            + " fetches a slice of the network database to start from. They carry nothing else,"
            + " and a client that has a router never asks them again.",
            true);
        readOnlyRow(reach, "Descriptor", data.descriptor,
            "Built from both lists. This is what a user pastes into their client.");

        var wiring = section(form, "This node's own wiring");
        var listen = endpointRow(wiring, "Operator API", data.listen,
            "Where the node answers the panel. Not a public address.", true);
        var messaging = endpointRow(wiring, "Messaging server", data.messaging,
            "The server-core this node is bound to: where it pushes quotas and reads mailboxes.",
            true);
        var level = chipRow(wiring, "How much the node writes to its log. Applies at once.",
            kLogLevels.map(function (name) { return { value: name, label: name }; }),
            data.logLevel || "info");

        var footer = saveFooter(form,
            "Addresses apply after a restart; the log level applies now.",
            function () {
                var facadeList = linesOf(facades);
                if (facadeList.length === 0) {
                    throw new Error("A server with no facade cannot be reached.");
                }
                var wrongFacade = facadeList.filter(function (url) { return !isI2pUrl(url); });
                if (wrongFacade.length > 0) {
                    throw new Error("A facade must be a .b32.i2p address: " + wrongFacade[0]);
                }
                var reseedList = linesOf(reseeds);
                var wrongReseed = reseedList.filter(isI2pUrl);
                if (wrongReseed.length > 0) {
                    throw new Error("A reseed must not be a .b32.i2p address - it is what a"
                        + " client without a router asks first: " + wrongReseed[0]);
                }
                return {
                    method: "PUT", path: withFleet("/api/settings"),
                    body: {
                        facades: facadeList,
                        reseeds: reseedList,
                        listen: {
                            host: listen.host.value.trim(),
                            port: portRead(listen.port, "The operator API")
                        },
                        messaging: {
                            host: messaging.host.value.trim(),
                            port: portRead(messaging.port, "The messaging server")
                        },
                        logLevel: level()
                    }
                };
            });
        restartButton(footer, "service-node", data.canRestart);
    }

    function renderAccountsTab(form, data) {
        var totals = element("ul", "facts");
        totals.appendChild(fact("accounts", String(data.accounts)));
        totals.appendChild(fact("allocated by quota", humanBytes(data.allocatedBytes)));
        totals.appendChild(fact("on disk", data.diskUsedBytes === null
            ? "unknown (" + data.diskError + ")"
            : humanBytes(data.diskUsedBytes)));
        form.appendChild(totals);

        var accounts = section(form, "What a new account gets");
        var quota = fieldRow(accounts, "Storage", Math.round(data.defaultQuotaBytes / kBytesPerMiB), {
            type: "number", narrow: true, min: kMinQuotaMiB, unit: "MB",
            hint: "The mailbox a registration is granted. The two numbers above say whether the"
                + " disk can still keep that promise."
        });
        var ttl = fieldRow(accounts, "Delete when idle for", data.idleDeleteDays, {
            type: "number", narrow: true, min: 0, unit: "days (0: forever)",
            hint: "An account with no destination delegated here for this long is deleted - a"
                + " client nobody runs, a registration nobody redeemed, an account nobody"
                + " approved."
        });

        saveFooter(form, "Applies now and is written to the node's config, so a restart keeps it.",
            function () {
                var megabytes = Number(quota.value);
                if (!Number.isFinite(megabytes) || megabytes < kMinQuotaMiB
                    || megabytes > kMaxQuotaMiB) {
                    throw new Error("Storage is a whole number of megabytes.");
                }
                return {
                    method: "PUT", path: withFleet("/api/settings"),
                    body: {
                        defaultQuotaBytes: Math.round(megabytes) * kBytesPerMiB,
                        idleDeleteDays: Math.max(0, Math.round(Number(ttl.value) || 0))
                    }
                };
            });
    }

    function renderServerTab(form, data) {
        var talk = section(form, "What the server says");
        var level = chipRow(talk, "Applies at once.",
            kLogLevels.map(function (name) { return { value: name, label: name }; }),
            data.logLevel || "info");
        var i2pLog = chipRow(talk,
            "libi2pd's own lines, folded into this server's log. Loud, and off unless a"
            + " tunnel problem is being chased. Applies at once.",
            [{ value: false, label: "i2p log off" }, { value: true, label: "i2p log on" }],
            Boolean(data.i2pLog));

        var i2p = section(form, "How this server sits on I2P");
        var privacy = chipRow(i2p,
            "Hops each tunnel takes. More hops, more anonymity, more latency: minimal is one"
            + " hop, max is three.",
            kPrivacyLevels.map(function (name) { return { value: name, label: name }; }),
            data.i2pPrivacy || "max");
        var tunnels = fieldRow(i2p, "Tunnels per address", data.i2pTunnelQuantity, {
            type: "number", narrow: true, min: 1, unit: "of 16", restart: true,
            hint: "Parallel tunnels carrying one destination. A public server's inbound"
                + " federation runs a full pool; lower it on a thin uplink."
        });

        var limits = section(form, "What it accepts and keeps");
        var rate = fieldRow(limits, "Inbound per peer", data.federationRateLimit, {
            type: "number", narrow: true, min: 1, unit: "deliveries / minute", restart: true,
            hint: "Per peer destination. It bounds one sender, not the server."
        });
        var retention = fieldRow(limits, "Keep unacknowledged mail", data.mailboxRetentionDays, {
            type: "number", narrow: true, min: 0, unit: "days (0: forever)", restart: true,
            hint: "The backstop for mail no device of the recipient ever collected. Mail that"
                + " every device acknowledged is deleted at once regardless."
        });

        var wiring = section(form, "Where it stands");
        var listen = endpointRow(wiring, "Listens on", data.listen,
            "The private channel the facade and the node reach it on. Never public.", true);
        var node = fieldRow(wiring, "Service node", data.serviceNode, {
            placeholder: "http://127.0.0.1:8421", restart: true,
            hint: "The node this server reports to."
        });
        readOnlyRow(wiring, "Fingerprint", data.fingerprint,
            "This server's identity. Clients pin it; it is not something to change.");
        readOnlyRow(wiring, "State", data.stateDirectory);
        readOnlyRow(wiring, "Version", data.version);

        var footer = saveFooter(form,
            "The log levels apply now; everything else is written for the next start.",
            function () {
                return {
                    method: "PUT",
                    path: withFleet("/api/service-settings?kind=server-core"),
                    body: {
                        logLevel: level(),
                        i2pLog: i2pLog(),
                        i2pPrivacy: privacy(),
                        i2pTunnelQuantity: Math.round(Number(tunnels.value) || 0),
                        federationRateLimit: Math.round(Number(rate.value) || 0),
                        mailboxRetentionDays: Math.max(0, Math.round(Number(retention.value) || 0)),
                        listen: {
                            host: listen.host.value.trim(),
                            port: portRead(listen.port, "The messaging server")
                        },
                        serviceNode: node.value.trim()
                    }
                };
            });
        restartButton(footer, "server-core", data.canRestart);
    }

    function renderFacadeTab(form, data) {
        var secret = section(form, "The secret prefix");
        var basePath = fieldRow(secret, "Base path", data.basePath, {
            placeholder: "/8f1818f3/0966179fb196", restart: true,
            hint: "The whole clearnet API - the reseed included - lives under this prefix, and"
                + " nothing outside it answers at all. It travels inside the facade URL of the"
                + " server descriptor, so changing it invalidates every descriptor already"
                + " handed out: update the facade list on the Addresses tab and re-issue the"
                + " descriptor before the old prefix goes away."
        });

        var talk = section(form, "What the facade says");
        var level = chipRow(talk, "Applies at once. The facade logs nothing identifying at any"
            + " level.",
            kLogLevels.map(function (name) { return { value: name, label: name }; }),
            data.logLevel || "info");

        var sockets = section(form, "Sockets");
        var listen = endpointRow(sockets, "Public", data.listen,
            "Where clients reach it, under the base path above.", true);
        var ops = endpointRow(sockets, "Operator", data.opsListen,
            "The private socket this page is talking to: health, settings, restart. Never"
            + " published to clients.", true);

        var backends = section(form, "What it forwards to");
        var messaging = endpointRow(backends, "Messaging server", data.messaging,
            "/v1/messaging/* goes here.", true);
        var account = endpointRow(backends, "Service node", data.account,
            "/v1/account/* goes here.", true);

        var i2p = section(form, "Its I2P side");
        var enabled = chipRow(i2p,
            "Whether the facade publishes destinations of its own. This is the address clients"
            + " should prefer: it needs no clearnet at all.",
            [{ value: true, label: "i2p on" }, { value: false, label: "i2p off" }],
            data.i2pEnabled !== false);
        var destinations = fieldRow(i2p, "Destinations", data.i2pDestinations, {
            type: "number", narrow: true, min: 1, unit: "addresses", restart: true,
            hint: "More than one spreads client traffic across separate addresses."
        });
        var privacy = chipRow(i2p, "Hops each tunnel takes.",
            kPrivacyLevels.map(function (name) { return { value: name, label: name }; }),
            data.i2pPrivacy || "max");
        var tunnels = fieldRow(i2p, "Tunnels per address", data.i2pTunnelQuantity, {
            type: "number", narrow: true, min: 1, unit: "of 16", restart: true
        });

        var facts = section(form, "What this facade is");
        readOnlyRow(facts, "State", data.stateDirectory,
            "Where its destination keys live, so its addresses survive a restart.");
        readOnlyRow(facts, "Version", data.version);

        var footer = saveFooter(form,
            "The log level applies now; everything else is written for the next start.",
            function () {
                var path = basePath.value.trim();
                if (path.length === 0 || path.charAt(0) !== "/" || path.slice(-1) === "/") {
                    throw new Error("A base path starts with / and does not end with one.");
                }
                return {
                    method: "PUT",
                    path: withFleet("/api/service-settings?kind=facade"),
                    body: {
                        basePath: path,
                        logLevel: level(),
                        listen: {
                            host: listen.host.value.trim(),
                            port: portRead(listen.port, "The public listener")
                        },
                        opsListen: {
                            host: ops.host.value.trim(),
                            port: portRead(ops.port, "The operator listener")
                        },
                        messaging: {
                            host: messaging.host.value.trim(),
                            port: portRead(messaging.port, "The messaging server")
                        },
                        account: {
                            host: account.host.value.trim(),
                            port: portRead(account.port, "The service node")
                        },
                        i2pEnabled: enabled(),
                        i2pDestinations: Math.round(Number(destinations.value) || 0),
                        i2pPrivacy: privacy(),
                        i2pTunnelQuantity: Math.round(Number(tunnels.value) || 0)
                    }
                };
            });
        restartButton(footer, "facade", data.canRestart);
    }

    function renderPanelTab(form, data) {
        var who = section(form, "Who may sign in");
        var admins = textareaBlock(who, (data.admins || []).join("\n"),
            "52-character fingerprint",
            "One fingerprint per line - `bazarish-client whoami`, or the Signature window in the"
            + " app. Removing the last one is refused: a panel with no administrator would be"
            + " handed to whoever opened its setup page next.");

        var consumer = data.consumer || {};
        var signing = section(form, "What an administrator sees before signing in");
        var name = fieldRow(signing, "Name", consumer.name, {
            limit: kConsumerNameMax, placeholder: "Bazarish admin panel",
            hint: "Shown in the client's window before you sign a login for this panel."
        });
        var place = fieldRow(signing, "Address", consumer.place, {
            limit: kConsumerPlaceMax, placeholder: "http://host:port",
            hint: "The address you have in the address bar when you sign in here."
        });
        var role = fieldRow(signing, "Role", consumer.role, {
            limit: kConsumerRoleMax, placeholder: "Administrator",
            hint: "What signing in here opens."
        });

        var services = section(form, "Services this panel manages");
        var rows = [];
        function serviceRow(fleetName, service) {
            var row = controls(services);
            var name = element("input", "field service-name");
            name.type = "text";
            name.placeholder = "core";
            name.value = service ? service.name : "";
            row.appendChild(name);
            var kind = element("select", "field service-kind");
            ["server-core", "service-node", "facade"].forEach(function (known) {
                var option = document.createElement("option");
                option.value = known;
                option.textContent = known;
                if (service && service.kind === known) {
                    option.selected = true;
                }
                kind.appendChild(option);
            });
            row.appendChild(kind);
            var url = element("input", "field");
            url.type = "text";
            url.placeholder = "http://127.0.0.1:8420";
            url.value = service ? service.url : "";
            row.appendChild(url);
            var drop = element("button", "chip", "remove");
            row.appendChild(drop);
            var entry = { fleet: fleetName, name: name, kind: kind, url: url, row: row,
                dropped: false };
            drop.addEventListener("click", function () {
                entry.dropped = true;
                row.remove();
            });
            rows.push(entry);
        }
        var fleets = data.fleets && data.fleets.length > 0
            ? data.fleets
            : [{ name: "server", services: [] }];
        var fleetName = fleets[0].name || "server";
        fleets.forEach(function (entry) {
            (entry.services || []).forEach(function (service) {
                serviceRow(entry.name || fleetName, service);
            });
        });
        var addRow = controls(services,
            "One deployment: a messaging server, the node bound to it, and the facades in front."
            + " The panel signs every call to them with its own key, so each service must carry"
            + " this panel's fingerprint in its operators list.");
        var add = element("button", "chip", "add service");
        add.addEventListener("click", function () {
            serviceRow(fleetName, null);
            services.insertBefore(rows[rows.length - 1].row, addRow);
        });
        addRow.appendChild(add);

        var where = section(form, "Where the panel listens");
        var listen = endpointRow(where, "Listens on", data.listen,
            "The socket this page is served on.", true);

        var facts = section(form, "What this panel is");
        readOnlyRow(facts, "Fingerprint", data.fingerprint,
            "The key the panel signs its calls to services with. Each service must list it as an"
            + " operator, or the panel gets a 403 from it.");
        readOnlyRow(facts, "Config file", data.configPath,
            "Where everything on this page is written back.");
        readOnlyRow(facts, "State", data.stateDir);
        readOnlyRow(facts, "Web files", data.assetsDir);
        readOnlyRow(facts, "Version", data.version);

        var footer = saveFooter(form,
            "Applies now, except the listener, which the panel picks up when it restarts.",
            function () {
                var list = linesOf(admins);
                if (list.length === 0) {
                    throw new Error("A panel needs at least one administrator.");
                }
                var services = rows.filter(function (entry) {
                    return !entry.dropped;
                }).map(function (entry) {
                    return {
                        name: entry.name.value.trim(),
                        kind: entry.kind.value,
                        url: entry.url.value.trim()
                    };
                });
                var incomplete = services.filter(function (service) {
                    return !service.name || !service.url;
                });
                if (incomplete.length > 0) {
                    throw new Error("A service needs a name and a URL.");
                }
                return {
                    method: "PUT", path: "/api/panel",
                    body: {
                        admins: list,
                        consumer: {
                            name: name.value.trim(),
                            place: place.value.trim(),
                            role: role.value.trim()
                        },
                        listen: {
                            host: listen.host.value.trim(),
                            port: portRead(listen.port, "The panel")
                        },
                        fleets: [{ name: fleetName, services: services }]
                    }
                };
            });
        // The panel is not one of the services it manages, so its own restart is
        // its own route.
        if (data.canRestart) {
            var restart = element("button", "chip", "restart panel");
            restart.addEventListener("click", function () {
                restart.disabled = true;
                restart.textContent = "restarting panel...";
                api("POST", "/api/panel/restart").then(function () {
                    window.setTimeout(function () { window.location.reload(); }, kRestartWaitMs);
                }).catch(function (error) {
                    restart.disabled = false;
                    restart.textContent = "restart panel";
                    footer.appendChild(notice(error.message, "is-error"));
                });
            });
            footer.appendChild(restart);
        }
    }

    // --- routing ----------------------------------------------------------

    var views = { monitoring: renderMonitoring, users: renderUsers, settings: renderSettings };

    // A hash the page writes itself must not redraw the page from the top.
    var ownHashWrite = false;

    function setHash(value) {
        if (window.location.hash === value) {
            return;
        }
        ownHashWrite = true;
        window.location.hash = value;
    }

    // The deployment picker in the sidebar. With one deployment there is nothing
    // to pick, so nothing is shown.
    function renderFleetPicker(names) {
        var slot = document.getElementById("fleets");
        if (!slot) {
            return;
        }
        slot.innerHTML = "";
        if (!names || names.length < 2) {
            fleet = names && names.length ? names[0] : "";
            return;
        }
        if (names.indexOf(fleet) < 0) {
            fleet = names[0];
        }
        slot.appendChild(element("p", "sidebar-note", "deployment"));
        names.forEach(function (name) {
            var chip = element("button", "chip" + (name === fleet ? " is-on" : ""), name);
            chip.addEventListener("click", function () {
                fleet = name;
                window.localStorage.setItem("bazarish.fleet", fleet);
                renderFleetPicker(names);
                route();
            });
            slot.appendChild(chip);
        });
    }

    function route() {
        window.clearInterval(pollTimer);
        pollTimer = null;
        var parts = (window.location.hash || "#/monitoring").replace("#/", "").split("/");
        var name = views[parts[0]] ? parts[0] : "monitoring";
        Array.prototype.forEach.call(nav.querySelectorAll("a"), function (link) {
            link.className = link.dataset.view === name ? "is-current" : "";
        });
        views[name](parts[1]);
    }

    // The deployments are learned from the same call monitoring makes.
    api("GET", "/api/services").then(function (data) {
        renderFleetPicker(data.fleets);
    }).catch(function () {
        // Nothing to pick from: the views will report the failure themselves.
    });

    window.addEventListener("hashchange", function () {
        if (ownHashWrite) {
            ownHashWrite = false;
            return;
        }
        route();
    });
    route();
})();
