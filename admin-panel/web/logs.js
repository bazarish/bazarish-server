// Bazarish project (c) 2026
(function () {
    "use strict";

    var kMaxLines = 2000;
    var kFollowSlackPx = 24;
    var kClockChars = 8;
    var kMillisPerSecond = 1000;
    var kMillisDigits = 3;

    var params = new URLSearchParams(window.location.search);
    var serviceName = params.get("service") || "";
    var kindName = params.get("kind") || "";
    var label = serviceName || kindName;

    var list = document.getElementById("logLines");
    var state = document.getElementById("logState");
    var pauseButton = document.getElementById("logPause");
    var reconnectButton = document.getElementById("logReconnect");
    var decoder = new TextDecoder();

    var instance = "";
    var lastSeq = 0;
    var paused = false;
    var held = [];
    var socket = null;
    var failure = "";

    function element(tag, className, text) {
        var node = document.createElement(tag);
        node.className = className;
        node.textContent = text;
        return node;
    }

    function clock(unixMillis) {
        var at = new Date(unixMillis);
        var millis = String(Math.abs(unixMillis) % kMillisPerSecond);
        return at.toTimeString().slice(0, kClockChars) + "." + millis.padStart(kMillisDigits, "0");
    }

    function lineNode(line) {
        var row = document.createElement("div");
        row.className = "log-line is-" + line.level;
        row.appendChild(element("span", "log-time", clock(line.t)));
        row.appendChild(element("span", "log-level", line.level));
        row.appendChild(element("span", "log-text", line.text));
        return row;
    }

    function mark(text) {
        return element("div", "log-mark", text);
    }

    function place(nodes) {
        var follow = list.scrollHeight - list.scrollTop - list.clientHeight <= kFollowSlackPx;
        var batch = document.createDocumentFragment();
        nodes.forEach(function (node) {
            batch.appendChild(node);
        });
        list.appendChild(batch);
        while (list.childElementCount > kMaxLines) {
            list.removeChild(list.firstElementChild);
        }
        if (follow) {
            list.scrollTop = list.scrollHeight;
        }
    }

    function deliver(nodes) {
        if (!paused) {
            place(nodes);
            return;
        }
        held = held.concat(nodes);
        if (held.length > kMaxLines) {
            held = held.slice(held.length - kMaxLines);
        }
    }

    function showState() {
        if (!socket) {
            state.textContent = failure ? t("Disconnected: %1", failure) : t("Disconnected");
            state.className = "log-state is-off";
            return;
        }
        if (socket.readyState !== WebSocket.OPEN) {
            state.textContent = t("Connecting");
            state.className = "log-state";
            return;
        }
        state.textContent = paused ? t("Paused") : t("Connected");
        state.className = "log-state" + (paused ? "" : " is-live");
    }

    function take(frame) {
        if (frame.type === "error") {
            failure = frame.message;
            return;
        }
        if (frame.type !== "lines") {
            return;
        }
        var nodes = [];
        if (instance && frame.instance !== instance) {
            nodes.push(mark(t("Service restarted")));
            lastSeq = 0;
        } else if (instance && frame.first > lastSeq + 1) {
            nodes.push(mark(t("%1 lines skipped", frame.first - lastSeq - 1)));
        }
        instance = frame.instance;
        frame.lines.forEach(function (line) {
            nodes.push(lineNode(line));
            lastSeq = line.seq;
        });
        deliver(nodes);
    }

    function socketUrl() {
        var query = new URLSearchParams();
        if (serviceName) {
            query.set("service", serviceName);
        } else {
            query.set("kind", kindName);
        }
        if (instance && lastSeq > 0) {
            query.set("after", String(lastSeq));
            query.set("instance", instance);
        }
        var scheme = window.location.protocol === "https:" ? "wss:" : "ws:";
        return scheme + "//" + window.location.host + "/api/logs?" + query.toString();
    }

    function connect() {
        failure = "";
        reconnectButton.hidden = true;
        socket = new WebSocket(socketUrl());
        socket.binaryType = "arraybuffer";
        socket.onopen = showState;
        socket.onmessage = function (event) {
            take(JSON.parse(decoder.decode(event.data)));
            showState();
        };
        socket.onclose = function () {
            socket = null;
            reconnectButton.hidden = false;
            showState();
        };
        showState();
    }

    pauseButton.addEventListener("click", function () {
        paused = !paused;
        pauseButton.textContent = paused ? t("Resume") : t("Pause");
        pauseButton.classList.toggle("is-on", paused);
        if (!paused && held.length > 0) {
            var waiting = held;
            held = [];
            place(waiting);
        }
        showState();
    });
    reconnectButton.addEventListener("click", connect);

    document.title = t("Logs: %1", label);
    document.getElementById("logTitle").textContent = label;
    connect();
}());
