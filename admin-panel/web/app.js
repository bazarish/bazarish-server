// Bazarish project (c) 2026
(function () {
    "use strict";

    var kHealthPollMs = 5000;
    var kSearchDebounceMs = 250;
    var kPageSize = 25;
    var kBytesPerMiB = 1024 * 1024;
    var kMinQuotaMiB = 1;
    var kMaxQuotaMiB = 1024 * 1024;
    var kSecondsPerMs = 1000;
    var kMinPort = 1;
    var kMaxPort = 65535;
    var kConsumerNameMax = 96;
    var kConsumerRoleMax = 48;
    var kDefaultHoldMessage = N_("Service for this account has been stopped");

    var content = document.getElementById("content");
    var fleet = window.localStorage.getItem("bazarish.fleet") || "";
    var nav = document.getElementById("nav");
    var pollTimer = null;

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

    function fact(label, value, beside) {
        var row = element("li");
        row.appendChild(element("span", "fact-label", t(label)));
        var side = element("span", "fact-value");
        side.appendChild(element("b", null, value));
        if (beside) {
            side.appendChild(beside);
        }
        row.appendChild(side);
        return row;
    }

    function isI2pUrl(url) {
        var withoutScheme = url.replace(/^[a-zA-Z]+:\/\//, "");
        var host = withoutScheme.split(/[:/]/)[0];
        return /\.b32\.i2p$/.test(host);
    }

    function humanBytes(bytes) {
        var units = [N_("B"), N_("KiB"), N_("MiB"), N_("GiB"), N_("TiB")];
        var value = Number(bytes) || 0;
        var unit = 0;
        while (value >= 1024 && unit + 1 < units.length) {
            value /= 1024;
            unit += 1;
        }
        return (value < 10 ? value.toFixed(1) : Math.round(value)) + " " + t(units[unit]);
    }

    function humanDate(unixSeconds) {
        if (!unixSeconds) {
            return t("never");
        }
        return new Date(unixSeconds * kSecondsPerMs).toISOString().replace("T", " ").slice(0, 16);
    }

    function notice(message, kind) {
        return element("p", "notice" + (kind ? " " + kind : ""), t(message));
    }

    function view(title) {
        content.innerHTML = "";
        var box = element("div", "view");
        box.appendChild(element("h1", "view-title", t(title)));
        content.appendChild(box);
        return box;
    }

    var kThousand = 1000;
    var kMillion = 1000 * kThousand;

    function humanCount(n) {
        var value = Number(n) || 0;
        if (value < kThousand) {
            return String(value);
        }
        return value < kMillion ? (value / kThousand).toFixed(1) + "k"
            : (value / kMillion).toFixed(1) + "M";
    }

    function settingsHref(service) {
        if (service.kind === "server-core") {
            return "#/settings/server";
        }
        if (service.kind === "service-node") {
            return "#/settings/addresses";
        }
        return "#/settings/" + (service.kind === "facade" ? "facades" : "gateways") + "/"
            + encodeURIComponent(service.name);
    }

    function serviceCard(service) {
        var card = element("div", "card");
        var head = element("div", "card-head");
        head.appendChild(element("i", "dot " + (service.up ? "is-up" : "is-down")));
        var name = element("a", "card-name item-link", service.name);
        name.href = settingsHref(service);
        name.addEventListener("click", function () {
            pickFleet(service.fleet);
        });
        head.appendChild(name);
        head.appendChild(element("span", "tag", service.up ? t("up") : t("down")));
        card.appendChild(head);

        var facts = element("ul", "facts");
        facts.appendChild(fact(N_("kind"), service.kind));
        facts.appendChild(fact(N_("address"), service.url));
        if (service.up) {
            facts.appendChild(fact(N_("version"), service.version || "-"));
            facts.appendChild(fact(N_("uptime"), service.uptime));
            facts.appendChild(fact(N_("memory"), t("%1 / %2 peak",
                humanBytes(service.ramBytes), humanBytes(service.ramPeakBytes))));
            if (service.kind === "facade") {
                facts.appendChild(fact(N_("requests"), t("%1/min  %2/h  %3/day",
                    humanCount(service.requestsLastMinute), humanCount(service.requestsLastHour),
                    humanCount(service.requestsLastDay))));
                facts.appendChild(fact(N_("in flight"), String(service.inFlight)));
            }
            if (service.kind === "gateway") {
                facts.appendChild(fact(N_("sessions"), humanCount(service.sessions)));
                facts.appendChild(fact(N_("destinations"), humanCount(service.destinations)));
                facts.appendChild(fact(N_("streams"), humanCount(service.streams)));
                facts.appendChild(fact(N_("refused"), humanCount(service.refused)));
                facts.appendChild(fact("i2pd", service.router || "-"));
            }
        } else {
            facts.appendChild(fact(N_("error"), (service.error || t("no answer"))
                + (service.status ? " (HTTP " + service.status + ")" : "")));
        }
        facts.appendChild(fact(N_("latency"), t("%1 ms", service.latencyMs)));
        card.appendChild(facts);
        return card;
    }

    function renderMonitoring() {
        var box = view(N_("monitoring"));
        var groups = element("div");
        box.appendChild(groups);

        function load() {
            api("GET", "/api/services").then(function (data) {
                groups.innerHTML = "";
                if (!data.services.length) {
                    groups.appendChild(element("p", "muted",
                        t("No services yet. Add them in Settings, Panel.")));
                    return;
                }
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

    function isDelegated(user) {
        return Boolean(user.transientExpires)
            && user.transientExpires * kSecondsPerMs > Date.now();
    }

    function stateTags(user) {
        var tags = element("span", "row-tags");
        if (user.banned) {
            tags.appendChild(element("span", "tag is-banned", t("banned")));
            return tags;
        }
        if (user.approval === "pending") {
            tags.appendChild(element("span", "tag is-pending", t("pending")));
        } else if (user.approval === "approved") {
            tags.appendChild(element("span", "tag is-approved", t("approved")));
        } else {
            tags.appendChild(element("span", "tag", t("no account")));
        }
        if (isDelegated(user)) {
            tags.appendChild(element("span", "tag is-live", t("delegated")));
        } else if (user.dest) {
            tags.appendChild(element("span", "tag is-pending", t("lapsed")));
        } else {
            tags.appendChild(element("span", "tag", t("no address")));
        }
        return tags;
    }

    function section(box, title) {
        var block = element("section", "block");
        if (title) {
            block.appendChild(element("h3", "block-title", t(title)));
        }
        box.appendChild(block);
        return block;
    }

    function controls(block, hint) {
        var row = element("div", "controls");
        block.appendChild(row);
        if (hint) {
            block.appendChild(element("p", "hint", t(hint)));
        }
        return row;
    }

    function actionButton(label, kind, run) {
        var button = element("button", "btn " + kind, t(label));
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
        }, t("Copy the fingerprint")));
        box.appendChild(head);

        var facts = element("ul", "facts");
        var approvals = { pending: N_("pending"), approved: N_("approved"), none: N_("none") };
        facts.appendChild(fact(N_("approval"),
            user.banned ? t("banned") : t(approvals[user.approval] || user.approval)));
        if (user.banned) {
            facts.appendChild(fact(N_("reason"), user.banReason || "-"));
        }
        if (user.holdMessage) {
            facts.appendChild(fact(N_("message"), user.holdMessage));
        }
        facts.appendChild(fact(N_("registered"), humanDate(user.registeredAt)));
        if (user.approval === "pending") {
            facts.appendChild(fact(N_("waiting since"), humanDate(user.requestedAt)));
        }
        if (user.approval === "approved") {
            facts.appendChild(fact(N_("approved"), humanDate(user.approvedAt)));
        }
        facts.appendChild(fact(N_("account"),
            user.registered ? t("registered") : t("not redeemed yet")));
        facts.appendChild(fact(N_("address"), user.dest || t("none published"),
            user.dest ? window.bazarishCopy.icon(function () {
                return user.dest;
            }, t("Copy the address")) : null));
        facts.appendChild(fact(N_("delegation"),
            isDelegated(user) ? t("until %1", humanDate(user.transientExpires))
                : (user.delegatedAt ? t("lapsed, last %1", humanDate(user.delegatedAt))
                    : t("none"))));
        var mailbox = fact(N_("mailbox"), "...");
        var devices = fact(N_("devices"), "...");
        facts.appendChild(mailbox);
        facts.appendChild(devices);
        api("GET", withFleet("/api/account?user=" + encodeURIComponent(user.user))).then(function (data) {
            mailbox.lastChild.textContent = t("%1 of %2",
                humanBytes(data.usedBytes), humanBytes(data.quotaBytes));
            devices.lastChild.textContent = String(data.devices);
        }).catch(function (error) {
            mailbox.lastChild.textContent = t("unknown (%1)", error.message);
            devices.lastChild.textContent = t("unknown");
        });
        if (user.sweepAt) {
            facts.appendChild(fact(N_("deleted unless it delegates"), humanDate(user.sweepAt)));
        }
        box.appendChild(facts);

        if (user.banned) {
            controls(section(box, N_("Ban")), N_("The key may register again"))
                .appendChild(actionButton(N_("Lift the ban"), "btn-quiet", function (done) {
                    api("POST", withFleet("/api/unban"), { user: user.user }).then(function () {
                        onChanged(t("Ban lifted"));
                    }).catch(function (error) {
                        done();
                        onError(error);
                    });
                }));
            return box;
        }

        var quotaBlock = section(box, N_("Storage quota"));
        var quotaRow = controls(quotaBlock);
        var quota = element("input", "field quota-input");
        quota.type = "number";
        quota.min = String(kMinQuotaMiB);
        quota.max = String(kMaxQuotaMiB);
        quota.step = "1";
        quota.value = String(Math.max(kMinQuotaMiB, Math.round(user.quotaBytes / kBytesPerMiB)));
        quotaRow.appendChild(quota);
        quotaRow.appendChild(element("span", "unit", t("MiB")));
        quotaRow.appendChild(actionButton(N_("Save"), "btn-quiet", function (done) {
            var megabytes = Number(quota.value);
            if (!Number.isFinite(megabytes) || megabytes < kMinQuotaMiB
                || megabytes > kMaxQuotaMiB) {
                done();
                onError(new Error(t("A quota is a whole number of MiB")));
                return;
            }
            api("PUT", withFleet("/api/quota"), {
                user: user.user,
                quotaBytes: Math.round(megabytes) * kBytesPerMiB
            }).then(function () {
                onChanged(t("Quota set to %1 MiB", Math.round(megabytes)));
            }).catch(function (error) {
                done();
                onError(error);
            });
        }));

        var onHold = user.approval === "pending" && Boolean(user.holdMessage);
        if (user.approval === "pending") {
            controls(section(box, onHold ? N_("Back into service") : N_("Approval")),
                onHold ? N_("The client republishes the address within a minute")
                    : N_("The account is served from now on"))
                .appendChild(actionButton(onHold ? N_("Return to service") : N_("Approve"), "",
                    function (done) {
                        api("POST", withFleet("/api/approve"), { user: user.user }).then(function () {
                            onChanged(onHold ? t("Back in service") : t("Approved"));
                        }).catch(function (error) {
                            done();
                            onError(error);
                        });
                    }));
        }

        if (user.approval === "approved" || onHold) {
            var holdBlock = section(box,
                onHold ? N_("Message to its owner") : N_("Take out of service"));
            var holdRow = controls(holdBlock, onHold
                ? N_("Replaces the line its owner reads. The account stays out of service.")
                : N_("Revokes the address. The account waits for approval again and its owner"
                    + " reads this line."));
            var holdNote = element("input", "field");
            holdNote.type = "text";
            holdNote.value = onHold ? user.holdMessage : t(kDefaultHoldMessage);
            holdRow.appendChild(holdNote);
            holdRow.appendChild(actionButton(onHold ? N_("Update message") : N_("Undelegate"),
                "btn-quiet",
                function (done) {
                    if (!holdNote.value.trim()) {
                        done();
                        onError(new Error(t("Say what you are stopping the account for")));
                        return;
                    }
                    api("POST", withFleet("/api/undelegate"), {
                        user: user.user,
                        message: holdNote.value.trim()
                    }).then(function () {
                        onChanged(onHold ? t("Message updated")
                            : t("Undelegated. The account is on hold."));
                    }).catch(function (error) {
                        done();
                        onError(error);
                    });
                }));
        }

        if (user.approval === "none") {
            section(box, N_("Approval")).appendChild(element("p", "hint",
                t("Registered at the portal, not redeemed by a client yet. Nothing to approve.")));
        }

        var removeBlock = section(box, N_("Delete"));
        controls(removeBlock,
            N_("Deletes the certificate, the grants and the address. The key may register again."))
            .appendChild(actionButton(N_("Delete account"), "btn-danger", function (done) {
                if (!window.confirm(t("Delete this account? The key may register again."))) {
                    done();
                    return;
                }
                api("POST", withFleet("/api/delete"), { user: user.user }).then(function () {
                    onGone(t("Account deleted"));
                }).catch(function (error) {
                    done();
                    onError(error);
                });
            }));

        var banRow = controls(section(box, N_("Ban")),
            N_("Deletes the account. This key does not register here again."));
        var banReason = element("input", "field");
        banReason.type = "text";
        banReason.placeholder = t("Reason shown to the key (default: Banned)");
        banRow.appendChild(banReason);
        banRow.appendChild(actionButton(N_("Ban key"), "btn-danger", function (done) {
            if (!window.confirm(t("Ban this key? It will not register here again."))) {
                done();
                return;
            }
            api("POST", withFleet("/api/ban"), {
                user: user.user,
                reason: banReason.value.trim()
            }).then(function () {
                onGone(t("Key banned"));
            }).catch(function (error) {
                done();
                onError(error);
            });
        }));

        return box;
    }

    function renderUsers(selected) {
        var box = view(N_("users"));

        var state = "all";
        var openUser = selected || null;
        var offset = 0;
        var total = 0;
        var loading = false;
        var exhausted = false;

        var toolbar = element("div", "toolbar");
        var search = element("input", "field search");
        search.type = "search";
        search.placeholder = t("Search by fingerprint or address");
        search.autocomplete = "off";
        toolbar.appendChild(search);

        var chips = {};
        [[ "all", N_("all")], ["pending", N_("pending")], ["approved", N_("approved")],
            ["banned", N_("banned")]].forEach(function (pair) {
            var name = pair[0];
            var chip = element("button", "chip" + (name === state ? " is-on" : ""), t(pair[1]));
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
            openRow = null;
            openDetail = null;
            rows.innerHTML = "";
            loadPage();
        }

        var openRow = null;
        var openDetail = null;

        function closeDetail() {
            if (openDetail) {
                openDetail.remove();
                openDetail = null;
            }
            if (openRow) {
                openRow.className = "row";
                openRow = null;
            }
        }

        function detailFor(user, row) {
            openRow = row;
            row.className = "row is-open";
            openDetail = userDetail(user, function (message) {
                say(message);
                reload();
            }, function (error) {
                say(error.message, "is-error");
            }, function (message) {
                openUser = null;
                setHash("#/users");
                say(message);
                reload();
            });
            rows.insertBefore(openDetail, row.nextSibling);
        }

        function addRow(user) {
            var row = element("button", "row");
            row.type = "button";
            var keys = element("span", "row-keys");
            keys.appendChild(element("span", "row-key", user.user));
            keys.appendChild(element("span", "row-dest", user.dest || t("no address published")));
            row.appendChild(keys);
            row.appendChild(stateTags(user));
            row.appendChild(element("span", "row-quota",
                t("%1 MiB", Math.round(user.quotaBytes / kBytesPerMiB))));
            row.addEventListener("click", function () {
                var opening = openUser !== user.user;
                closeDetail();
                openUser = opening ? user.user : null;
                setHash(openUser ? "#/users/" + openUser : "#/users");
                if (opening) {
                    detailFor(user, row);
                }
            });
            rows.appendChild(row);
            if (openUser === user.user) {
                detailFor(user, row);
            }
        }

        function loadPage() {
            if (loading || exhausted) {
                return;
            }
            loading = true;
            more.textContent = t("Loading...");
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
                    ? t("Accounts: %1", total)
                    : t("Accounts: %1 of %2", offset, total);
                more.textContent = exhausted ? "" : t("Scroll for more");
                if (!rows.children.length) {
                    rows.appendChild(element("p", "muted", t("Nothing here")));
                }
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

    var kSettingsTabs = [
        { id: "panel", label: N_("Panel") },
        { id: "registration", label: N_("Registration") },
        { id: "portal", label: N_("Portal") },
        { id: "addresses", label: N_("Addresses") },
        { id: "accounts", label: N_("Accounts") },
        { id: "server", label: N_("Server") },
        { id: "facades", label: N_("Facades") },
        { id: "gateways", label: N_("Gateways") }
    ];
    var kLogLevels = ["error", "warn", "info", "debug"];
    var kServiceKinds = ["server-core", "service-node", "facade", "gateway"];
    var kPrivacyLevels = ["minimal", "middle", "max"];
    var kRestartWaitMs = 10000;
    var settingsTab = kSettingsTabs[0].id;
    var settingsItem = "";

    function showQr(text) {
        api("POST", "/api/qr", { text: text }).then(function (answer) {
            var sheet = element("dialog", "qr-sheet");
            var picture = element("img", "qr-picture");
            picture.alt = t("QR code");
            picture.src = "data:image/svg+xml;charset=utf-8," + encodeURIComponent(answer.svg);
            var close = element("button", "btn btn-quiet", t("Close"));
            close.type = "button";
            close.addEventListener("click", function () { sheet.close(); });
            sheet.addEventListener("close", function () { sheet.remove(); });
            sheet.addEventListener("click", function (event) {
                if (event.target === sheet) {
                    sheet.close();
                }
            });
            sheet.appendChild(picture);
            sheet.appendChild(close);
            document.body.appendChild(sheet);
            sheet.showModal();
        }).catch(function (error) {
            window.alert(error.message);
        });
    }

    function shareButtons(row, text) {
        row.appendChild(window.bazarishCopy.button(t("Copy"), function () { return text; }));
        var qr = element("button", "btn btn-quiet btn-copy", "QR");
        qr.type = "button";
        qr.addEventListener("click", function () { showQr(text); });
        row.appendChild(qr);
    }

    function restartBadge() {
        var badge = element("span", "badge-restart", t("restart"));
        badge.title = t("Takes effect at the next start of the service");
        return badge;
    }

    function fieldRow(block, label, value, spec) {
        var options = spec || {};
        var row = controls(block, options.hint);
        row.appendChild(element("span", "control-label", t(label)));
        var input = element("input", "field" + (options.narrow ? " quota-input" : ""));
        input.type = options.type || "text";
        if (options.limit) {
            input.maxLength = options.limit;
        }
        if (options.min !== undefined) {
            input.min = String(options.min);
        }
        if (options.max !== undefined) {
            input.max = String(options.max);
        }
        if (options.placeholder) {
            input.placeholder = t(options.placeholder);
        }
        input.value = value === null || value === undefined ? "" : String(value);
        row.appendChild(input);
        if (options.unit) {
            row.appendChild(element("span", "unit", t(options.unit)));
        }
        if (options.restart) {
            row.appendChild(restartBadge());
        }
        return input;
    }

    function readOnlyRow(block, label, value, hint) {
        var row = controls(block, hint);
        row.appendChild(element("span", "control-label", t(label)));
        var unset = value === null || value === undefined || value === "";
        row.appendChild(element("span", "readonly" + (unset ? " is-unset" : ""),
            unset ? t("not set") : String(value)));
        return row;
    }

    function endpointRow(block, label, endpoint, hint, restart) {
        var value = endpoint || {};
        var row = controls(block, hint);
        row.appendChild(element("span", "control-label", t(label)));
        var host = element("input", "field");
        host.type = "text";
        host.value = value.host || "";
        host.placeholder = "127.0.0.1";
        row.appendChild(host);
        var port = element("input", "field quota-input");
        port.type = "number";
        port.min = String(kMinPort);
        port.max = String(kMaxPort);
        port.value = value.port ? String(value.port) : "";
        row.appendChild(port);
        if (restart) {
            row.appendChild(restartBadge());
        }
        return { host: host, port: port };
    }

    function chipRow(block, label, hint, choices, current, spec) {
        var options = spec || {};
        var row = controls(block, hint);
        if (label) {
            row.appendChild(element("span", "control-label", t(label)));
        }
        var chips = {};
        var picked = current;
        choices.forEach(function (choice) {
            var chip = element("button", "chip" + (choice.value === picked ? " is-on" : ""),
                t(choice.label));
            chip.addEventListener("click", function () {
                picked = choice.value;
                Object.keys(chips).forEach(function (key) {
                    chips[key].className = "chip" + (key === String(picked) ? " is-on" : "");
                });
                if (options.onPick) {
                    options.onPick(picked);
                }
            });
            chips[String(choice.value)] = chip;
            row.appendChild(chip);
        });
        if (options.restart) {
            row.appendChild(restartBadge());
        }
        return function () { return picked; };
    }

    function textareaBlock(block, label, value, placeholder, hint, tall) {
        block.appendChild(element("p", "field-label", t(label)));
        var area = element("textarea", "field" + (tall ? " field-tall" : ""));
        area.value = value || "";
        area.placeholder = t(placeholder);
        controls(block, hint).appendChild(area);
        return area;
    }

    function sameUrl(one, other) {
        return one.replace(/\/+$/, "") === other.replace(/\/+$/, "");
    }

    // The portal's addresses, each of which can also be one of the reseeds it serves.
    function linkList(block, links, reseeds) {
        block.appendChild(element("p", "field-label", t("Addresses")));
        var wrap = element("div", "link-list");
        var list = element("div", "link-rows");
        wrap.appendChild(list);
        controls(block, N_("A client shows them to a person with no account here, and a user"
            + " compares them with the address bar before signing. The portal serves the reseed"
            + " at each of them.")).appendChild(wrap);
        var rows = [];
        function addRow(address) {
            var row = element("div", "link-row");
            var url = element("input", "field");
            url.type = "text";
            url.placeholder = "https://host:port";
            url.value = address;
            var label = element("label", "link-reseed");
            var reseed = element("input");
            reseed.type = "checkbox";
            reseed.checked = reseeds.some(function (held) { return sameUrl(held, address); });
            label.appendChild(reseed);
            label.appendChild(document.createTextNode(t("Add to reseeds")));
            var drop = element("button", "chip", t("remove"));
            drop.type = "button";
            var entry = { url: url, reseed: reseed, dropped: false };
            function followScheme() {
                var secure = /^https:\/\//.test(url.value.trim());
                reseed.disabled = !secure;
                if (!secure) {
                    reseed.checked = false;
                }
            }
            url.addEventListener("input", followScheme);
            drop.addEventListener("click", function () {
                entry.dropped = true;
                row.remove();
            });
            followScheme();
            row.appendChild(url);
            row.appendChild(label);
            row.appendChild(drop);
            list.appendChild(row);
            rows.push(entry);
        }
        links.forEach(addRow);
        var add = element("button", "chip link-add", t("add address"));
        add.type = "button";
        add.addEventListener("click", function () { addRow(""); });
        wrap.appendChild(add);
        function kept() {
            return rows.filter(function (entry) {
                return !entry.dropped && entry.url.value.trim().length > 0;
            });
        }
        return {
            addresses: function () {
                return kept().map(function (entry) { return entry.url.value.trim(); });
            },
            reseeds: function () {
                var mine = links.concat(kept().map(function (entry) {
                    return entry.url.value.trim();
                }));
                var others = reseeds.filter(function (held) {
                    return !mine.some(function (link) { return sameUrl(link, held); });
                });
                return kept().filter(function (entry) { return entry.reseed.checked; })
                    .map(function (entry) { return entry.url.value.trim(); }).concat(others);
            }
        };
    }

    function linesOf(area) {
        return area.value.split("\n").map(function (line) {
            return line.trim();
        }).filter(function (line) {
            return line.length > 0;
        });
    }

    function saveFooter(form, note, gather) {
        var footer = element("div", "form-footer");
        var save = element("button", "btn", t("Save"));
        footer.appendChild(save);
        footer.appendChild(element("span", "hint", t(note)));
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
            api(call.method, call.path, call.body).then(function (data) {
                if (call.after && call.after(data, footer)) {
                    save.disabled = false;
                    return;
                }
                renderSettings();
            }).catch(function (error) {
                save.disabled = false;
                footer.appendChild(notice(error.message, "is-error"));
            });
        });
        return footer;
    }

    function linkNotices(errors, at) {
        (errors || []).forEach(function (failed) {
            at.appendChild(notice(t("Saved, but the gateways were not linked: %1",
                failed.error || failed), "is-error"));
        });
        return Boolean(errors && errors.length);
    }

    function serviceQuery(target) {
        return target.service ? "service=" + encodeURIComponent(target.service)
            : "kind=" + encodeURIComponent(target.kind);
    }

    function restartButton(footer, target) {
        var label = target.service || target.kind;
        var button = element("button", "chip", t("restart %1", label));
        button.addEventListener("click", function () {
            button.disabled = true;
            button.textContent = t("restarting %1...", label);
            api("POST", withFleet("/api/restart?" + serviceQuery(target)))
                .then(function () {
                    window.setTimeout(renderSettings, kRestartWaitMs);
                })
                .catch(function (error) {
                    button.disabled = false;
                    button.textContent = t("restart %1", label);
                    footer.appendChild(notice(error.message, "is-error"));
                });
        });
        footer.appendChild(button);
    }

    function portRead(input, what) {
        var port = Number(input.value);
        if (!Number.isInteger(port) || port < kMinPort || port > kMaxPort) {
            throw new Error(t("%1 needs a port between %2 and %3", t(what), kMinPort, kMaxPort));
        }
        return port;
    }

    function renderSettings(wanted, item) {
        if (wanted && kSettingsTabs.some(function (tab) { return tab.id === wanted; })) {
            settingsTab = wanted;
            settingsItem = item || "";
        }
        setHash("#/settings/" + settingsTab
            + (settingsItem ? "/" + encodeURIComponent(settingsItem) : ""));
        var box = view(N_("settings"));
        var bar = element("nav", "tabs");
        kSettingsTabs.forEach(function (tab) {
            var button = element("button", "tab" + (tab.id === settingsTab ? " is-on" : ""),
                t(tab.label));
            button.addEventListener("click", function () {
                renderSettings(tab.id);
            });
            bar.appendChild(button);
        });
        box.appendChild(bar);

        var form = element("div", "panel-box");
        box.appendChild(form);
        form.appendChild(element("p", "muted", t("Loading...")));

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

        function fill(path, render) {
            api("GET", withFleet(path)).then(function (data) {
                form.innerHTML = "";
                render(form, data);
            }).catch(function (error) {
                form.innerHTML = "";
                form.appendChild(notice(error.message, "is-error"));
            });
        }

        if (settingsTab === "server") {
            fill("/api/service-settings?kind=server-core", renderServerTab);
            return;
        }
        if (settingsTab === "facades" || settingsTab === "gateways") {
            var facades = settingsTab === "facades";
            if (!settingsItem) {
                fill(facades ? "/api/facades" : "/api/services",
                    facades ? renderFacadeList : renderGatewayList);
                return;
            }
            var name = settingsItem;
            fill("/api/service-settings?service=" + encodeURIComponent(name),
                function (box, data) {
                    (facades ? renderFacadePage : renderGatewayPage)(box, name, data);
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
        var says;
        var how = section(form, N_("Who gets an account"));
        var moderated = chipRow(how, "",
            N_("Open: an account is served as soon as it registers. Moderated: it waits for you."),
            [{ value: false, label: N_("open") }, { value: true, label: N_("moderated") }],
            Boolean(data.requireApproval),
            { onPick: function (picked) { says.hidden = !picked; } });

        says = section(form, N_("What people are told"));
        says.hidden = !data.requireApproval;
        var portalMessage = textareaBlock(says, N_("Before registering"), data.portalMessage,
            N_("What this server is, and what registering here means"),
            N_("Shown by a client that reaches this server without an account here"));
        var waiting = textareaBlock(says, N_("While waiting"), data.registrationMessage,
            N_("How to reach you"),
            N_("Shown to an account that is registered and not served yet"));

        var footer = saveFooter(form,
            N_("Applies now and is written to the node's config, so a restart keeps it"),
            function () {
                return {
                    method: "PUT", path: withFleet("/api/settings"),
                    body: {
                        requireApproval: moderated(),
                        portalMessage: portalMessage.value.trim(),
                        registrationMessage: waiting.value.trim()
                    }
                };
            });
        restartButton(footer, { kind: "service-node" });
    }

    function renderPortalTab(form, data) {
        var consumer = data.loginConsumer || {};
        var signing = section(form, N_("What a user sees before signing in"));
        var name = fieldRow(signing, N_("Name"), consumer.name, {
            limit: kConsumerNameMax, placeholder: N_("The name of this site"),
            hint: N_("Shown in the client's window before a user signs a login for this portal")
        });
        var addresses = (consumer.place || []).slice();
        (data.portalLinks || []).forEach(function (link) {
            if (!addresses.some(function (held) { return sameUrl(held, link); })) {
                addresses.push(link);
            }
        });
        var links = linkList(signing, addresses, data.reseeds || []);
        var role = fieldRow(signing, N_("Role"), consumer.role, {
            limit: kConsumerRoleMax, placeholder: N_("Account owner"),
            hint: N_("Whose account the signature is for")
        });

        var reach = section(form, N_("Where the portal answers"));
        var listen = endpointRow(reach, N_("Listens on"), data.portalListen,
            N_("The socket the portal binds. It serves the reseed too."), true);

        var footer = saveFooter(form,
            N_("The words apply to the next challenge; the listener needs a restart"),
            function () {
                var signer = {
                    name: name.value.trim(), place: links.addresses(), role: role.value.trim()
                };
                var missing = Object.keys(signer).filter(function (key) {
                    return signer[key].length === 0;
                });
                if (missing.length > 0) {
                    var fields = { name: N_("name"), place: N_("addresses"), role: N_("role") };
                    throw new Error(t("A sign-in challenge needs its %1", t(fields[missing[0]])));
                }
                return {
                    method: "PUT", path: withFleet("/api/settings"),
                    body: {
                        loginConsumer: signer,
                        portalLinks: links.addresses(),
                        reseeds: links.reseeds(),
                        portalListen: {
                            host: listen.host.value.trim(),
                            port: portRead(listen.port, N_("The portal"))
                        }
                    }
                };
            });
        restartButton(footer, { kind: "service-node" });
    }

    function renderAddressesTab(form, data) {
        var reach = section(form, N_("How clients reach this server"));
        var reported = data.facades || [];
        if (reported.length === 0) {
            readOnlyRow(reach, N_("Facades"), "");
        }
        reported.forEach(function (address, index) {
            readOnlyRow(reach, index === 0 ? N_("Facades") : "", address);
        });
        reach.appendChild(element("p", "hint", t("Each facade reports its own address, and the"
            + " panel writes them here in the order of Settings, Panel. See the Facades tab.")));
        var reseeds = textareaBlock(reach, N_("Reseeds"), (data.reseeds || []).join("\n"),
            "https://host:port/<base path>",
            N_("One per line. A client with no I2P router fetches the network database here."),
            true);
        var descriptorRow = readOnlyRow(reach, N_("Descriptor"), data.descriptor,
            N_("Built from the facades and the reseeds. This is what a user pastes into their"
            + " client."));
        if (data.descriptor) {
            shareButtons(descriptorRow, data.descriptor);
        }

        var wiring = section(form, N_("This node's own wiring"));
        var listen = endpointRow(wiring, "API", data.listen,
            N_("Facades and the messaging server reach the node here. Not a public address."),
            true);
        var messaging = endpointRow(wiring, N_("Messaging server"), data.messaging,
            N_("The server-core this node is bound to: where it pushes quotas and reads mailboxes"),
            true);
        var level = chipRow(wiring, N_("Log level"), N_("Applies at once"),
            kLogLevels.map(function (name) { return { value: name, label: name }; }),
            data.logLevel || "info");

        var footer = saveFooter(form,
            N_("Addresses and the log level apply now; the sockets need a restart"),
            function () {
                var reseedList = linesOf(reseeds);
                var wrongReseed = reseedList.filter(isI2pUrl);
                if (wrongReseed.length > 0) {
                    throw new Error(t("A reseed must not be a .b32.i2p address - it is what a"
                        + " client without a router asks first: %1", wrongReseed[0]));
                }
                return {
                    method: "PUT", path: withFleet("/api/settings"),
                    body: {
                        reseeds: reseedList,
                        listen: {
                            host: listen.host.value.trim(),
                            port: portRead(listen.port, N_("The API listener"))
                        },
                        messaging: {
                            host: messaging.host.value.trim(),
                            port: portRead(messaging.port, N_("The messaging server"))
                        },
                        logLevel: level()
                    }
                };
            });
        restartButton(footer, { kind: "service-node" });
    }

    function renderAccountsTab(form, data) {
        var totals = element("ul", "facts");
        totals.appendChild(fact(N_("accounts"), String(data.accounts)));
        totals.appendChild(fact(N_("allocated by quota"), humanBytes(data.allocatedBytes)));
        totals.appendChild(fact(N_("on disk"), data.diskUsedBytes === null
            ? t("unknown (%1)", data.diskError)
            : humanBytes(data.diskUsedBytes)));
        form.appendChild(totals);

        var accounts = section(form, N_("What a new account gets"));
        var quota = fieldRow(accounts, N_("Storage"),
            Math.round(data.defaultQuotaBytes / kBytesPerMiB), {
                type: "number", narrow: true, min: kMinQuotaMiB, max: kMaxQuotaMiB, unit: N_("MiB"),
                hint: N_("The mailbox a registration is granted")
            });
        var ttl = fieldRow(accounts, N_("Delete when idle for"), data.idleDeleteDays, {
            type: "number", narrow: true, min: 0, unit: N_("days (0: forever)"),
            hint: N_("An account that delegates no address for this long is deleted")
        });

        saveFooter(form,
            N_("Applies now and is written to the node's config, so a restart keeps it"),
            function () {
                var megabytes = Number(quota.value);
                if (!Number.isFinite(megabytes) || megabytes < kMinQuotaMiB
                    || megabytes > kMaxQuotaMiB) {
                    throw new Error(t("Storage is a whole number of MiB"));
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
        var talk = section(form, N_("What the server says"));
        var level = chipRow(talk, N_("Log level"), N_("Applies at once"),
            kLogLevels.map(function (name) { return { value: name, label: name }; }),
            data.logLevel || "info");
        var i2pLog = chipRow(talk, N_("i2pd log"),
            N_("libi2pd's own lines in this server's log. Loud. Applies at once."),
            [{ value: false, label: N_("off") }, { value: true, label: N_("on") }],
            Boolean(data.i2pLog));

        var i2p = section(form, N_("How this server sits on I2P"));
        var privacy = chipRow(i2p, N_("Privacy"),
            N_("Hops each tunnel takes: minimal is one, max is three"),
            kPrivacyLevels.map(function (name) { return { value: name, label: name }; }),
            data.i2pPrivacy || "max", { restart: true });
        var tunnels = fieldRow(i2p, N_("Tunnels per address"), data.i2pTunnelQuantity, {
            type: "number", narrow: true, min: 1, max: data.i2pTunnelQuantityMax,
            unit: t("of %1", data.i2pTunnelQuantityMax), restart: true,
            hint: N_("Parallel tunnels per destination. Lower it on a thin uplink.")
        });

        var wiring = section(form, N_("Where it stands"));
        var listen = endpointRow(wiring, N_("Listens on"), data.listen,
            N_("The private channel the facade and the node reach it on. Never public."), true);
        var gatewaysAt = endpointRow(wiring, N_("Gateways reach it on"), data.gatewayListen,
            N_("This deployment's gateways carry their users' streams to the server here, without"
                + " I2P. Never public."), true);
        var node = fieldRow(wiring, N_("Service node"), data.serviceNode, {
            placeholder: "http://127.0.0.1:8421", restart: true,
            hint: N_("The node this server reports to")
        });
        readOnlyRow(wiring, N_("Fingerprint"), data.fingerprint,
            N_("This server's identity. Clients pin it."));
        readOnlyRow(wiring, N_("State"), data.stateDirectory);
        readOnlyRow(wiring, N_("Version"), data.version);

        var footer = saveFooter(form,
            N_("The log levels apply now; everything else is written for the next start"),
            function () {
                var body = {
                    logLevel: level(),
                    i2pLog: i2pLog(),
                    i2pPrivacy: privacy(),
                    i2pTunnelQuantity: Math.round(Number(tunnels.value) || 0),
                    listen: {
                        host: listen.host.value.trim(),
                        port: portRead(listen.port, N_("The messaging server"))
                    },
                    serviceNode: node.value.trim()
                };
                if (gatewaysAt.host.value.trim() !== "" || gatewaysAt.port.value !== "") {
                    body.gatewayListen = {
                        host: gatewaysAt.host.value.trim(),
                        port: portRead(gatewaysAt.port, N_("The gateways' socket"))
                    };
                }
                return {
                    method: "PUT",
                    path: withFleet("/api/service-settings?kind=server-core"),
                    body: body,
                    after: function (answer, at) { return linkNotices(answer.gatewayLinkErrors, at); }
                };
            });
        restartButton(footer, { kind: "server-core" });
    }

    function itemHead(form, tab, label, name) {
        var back = element("a", "item-link item-back", t(label));
        back.href = "#/settings/" + tab;
        form.appendChild(back);
        form.appendChild(element("h2", "item-title", name));
    }

    function itemRow(list, name, href, value, tags) {
        var row = element("li");
        var link = element("a", "fact-label item-link", name);
        link.href = href;
        row.appendChild(link);
        var side = element("span", "fact-value");
        side.appendChild(element("b", null, value));
        tags.forEach(function (tag) {
            side.appendChild(element("span", "tag" + (tag.kind ? " " + tag.kind : ""), t(tag.text)));
        });
        row.appendChild(side);
        list.appendChild(row);
    }

    function renderFacadeList(form, data) {
        if (data.descriptorError) {
            form.appendChild(notice(t("The descriptor could not be read: %1", data.descriptorError),
                "is-error"));
        }
        if (!data.facades.length) {
            form.appendChild(element("p", "muted",
                t("No facades yet. Add them in Settings, Panel.")));
            return;
        }
        var list = element("ul", "facts");
        data.facades.forEach(function (facade) {
            var tags = facade.error ? [{ text: N_("down"), kind: "is-pending" }]
                : [facade.inDescriptor ? { text: N_("up"), kind: "is-approved" }
                    : { text: N_("not in the descriptor"), kind: "is-pending" }];
            itemRow(list, facade.name, "#/settings/facades/" + encodeURIComponent(facade.name),
                facade.error || facade.address, tags);
        });
        form.appendChild(list);
        form.appendChild(element("p", "hint", t("Each facade reports its own address. The panel"
            + " writes them into the descriptor, in the order of Settings, Panel, whenever that"
            + " list is saved or a facade gets a new address")));
    }

    function renderFacadePage(form, name, data) {
        itemHead(form, "facades", N_("all facades"), name);
        var address = section(form, N_("Its address"));
        var shown = readOnlyRow(address, N_("Address"), data.address,
            N_("Its I2P destination, minted at its first start"));
        var said = element("div");
        address.appendChild(said);
        controls(address, N_("Replaces the key and restarts the facade. The"
            + " descriptor and any gateway route to the old address follow by themselves; a"
            + " client that knows only the old address loses the server until it is given the"
            + " new link")).appendChild(actionButton(N_("New address"), "btn-danger",
            function (done) {
            if (!window.confirm(t("Give %1 a new address? Clients that know only the"
                + " old one lose the server until they are given the new link.", name))) {
                done();
                return;
            }
            api("POST", withFleet("/api/facade/new-address?service=" + encodeURIComponent(name)))
                .then(function (answer) {
                    shown.lastChild.textContent = answer.address;
                    said.innerHTML = "";
                    said.appendChild(notice(answer.descriptorError
                        ? t("The descriptor was not changed: %1", answer.descriptorError)
                        : t("The descriptor carries the new address"),
                        answer.descriptorError ? "is-error" : ""));
                    answer.gateways.forEach(function (gateway) {
                        if (gateway.error) {
                            said.appendChild(notice(t("Gateway %1 was not reached: %2",
                                gateway.name, gateway.error), "is-error"));
                        } else if (gateway.changed) {
                            said.appendChild(notice(t("Gateway %1 routes the new address directly",
                                gateway.name)));
                        }
                    });
                    done();
                }).catch(function (error) {
                    said.innerHTML = "";
                    said.appendChild(notice(error.message, "is-error"));
                    done();
                });
        }));

        var talk = section(form, N_("What the facade says"));
        var level = chipRow(talk, N_("Log level"), N_("Applies at once"),
            kLogLevels.map(function (level) { return { value: level, label: level }; }),
            data.logLevel || "info");

        var sockets = section(form, N_("Sockets"));
        var listen = endpointRow(sockets, "API", data.listen,
            N_("What its I2P address relays to. Keep it on loopback."), true);
        var ops = endpointRow(sockets, N_("Operator"), data.opsListen,
            N_("The private socket this page is talking to: health, settings, restart. Never"
            + " published to clients."), true);
        var direct = endpointRow(sockets, N_("Direct"), data.directListen,
            N_("What the I2P address serves, over TLS, for a gateway given a route here. Empty:"
            + " not opened."), true);

        var backends = section(form, N_("What it forwards to"));
        var messaging = endpointRow(backends, N_("Messaging server"), data.messaging,
            N_("The messaging tunnel and the server card go here"), true);
        var serviceNode = endpointRow(backends, N_("Service node"), data.serviceNode,
            N_("The account tunnel and the node card go here"), true);

        var i2p = section(form, N_("Its I2P address"));
        var privacy = chipRow(i2p, N_("Privacy"),
            N_("Hops each tunnel takes: minimal is one, max is three"),
            kPrivacyLevels.map(function (level) { return { value: level, label: level }; }),
            data.i2pPrivacy || "max", { restart: true });
        var tunnels = fieldRow(i2p, N_("Tunnels"), data.i2pTunnelQuantity, {
            type: "number", narrow: true, min: 1, max: data.i2pTunnelQuantityMax,
            unit: t("of %1", data.i2pTunnelQuantityMax), restart: true
        });

        var facts = section(form, N_("What this facade is"));
        readOnlyRow(facts, N_("State"), data.stateDirectory,
            N_("Where its keys live, so its address survives a restart"));
        readOnlyRow(facts, N_("Version"), data.version);

        var footer = saveFooter(form,
            N_("The log level applies now; everything else is written for the next start"),
            function () {
                var request = {
                    method: "PUT",
                    path: withFleet("/api/service-settings?service=" + encodeURIComponent(name)),
                    after: function (answer, at) { return linkNotices(answer.gatewayLinkErrors, at); },
                    body: {
                        logLevel: level(),
                        listen: {
                            host: listen.host.value.trim(),
                            port: portRead(listen.port, N_("The API listener"))
                        },
                        opsListen: {
                            host: ops.host.value.trim(),
                            port: portRead(ops.port, N_("The operator listener"))
                        },
                        messaging: {
                            host: messaging.host.value.trim(),
                            port: portRead(messaging.port, N_("The messaging server"))
                        },
                        serviceNode: {
                            host: serviceNode.host.value.trim(),
                            port: portRead(serviceNode.port, N_("The service node"))
                        },
                        i2pPrivacy: privacy(),
                        i2pTunnelQuantity: Math.round(Number(tunnels.value) || 0)
                    }
                };
                if (direct.host.value.trim() !== "" || direct.port.value !== "") {
                    request.body.directListen = {
                        host: direct.host.value.trim(),
                        port: portRead(direct.port, N_("The direct listener"))
                    };
                }
                return request;
            });
        restartButton(footer, { service: name });
    }

    function renderGatewayList(form, data) {
        var mine = data.services.filter(function (service) {
            return service.kind === "gateway" && (!fleet || service.fleet === fleet);
        });
        if (!mine.length) {
            form.appendChild(element("p", "muted",
                t("No gateways yet. Add them in Settings, Panel.")));
            return;
        }
        var list = element("ul", "facts");
        mine.forEach(function (gateway) {
            itemRow(list, gateway.name, "#/settings/gateways/" + encodeURIComponent(gateway.name),
                gateway.up ? t("sessions: %1, destinations: %2", humanCount(gateway.sessions),
                    humanCount(gateway.destinations))
                    : (gateway.error || t("no answer")),
                [gateway.up ? { text: N_("up"), kind: "is-approved" }
                    : { text: N_("down"), kind: "is-pending" }]);
        });
        form.appendChild(list);
    }

    function renderGatewayPage(form, name, data) {
        itemHead(form, "gateways", N_("all gateways"), name);
        var tunnels = section(form, N_("Tunnels"));
        var privacy = chipRow(tunnels, N_("Privacy"), t("Hops each tunnel takes, for every client"
            + " of this gateway: minimal is one, max is three. Call media is always %1.",
            data.callPrivacy),
            kPrivacyLevels.map(function (level) { return { value: level, label: level }; }),
            data.i2pPrivacy || "minimal", { restart: true });
        var quantity = fieldRow(tunnels, N_("Tunnels"), data.i2pTunnelQuantity, {
            type: "number", narrow: true, min: 1, max: data.i2pTunnelQuantityMax,
            unit: t("of %1", data.i2pTunnelQuantityMax), restart: true,
            hint: N_("Per destination. Lower it on a thin uplink.")
        });

        var pools = section(form, N_("Warm pools"));
        var streamPool = fieldRow(pools, N_("Streams"), data.streamPool, {
            type: "number", narrow: true, min: 0, max: data.poolMax,
            unit: t("of %1", data.poolMax), restart: true,
            hint: N_("Unpublished destinations kept built with the tunnels above: what a facade"
                + " link, a lookup or a file takes. 0 builds each on demand.")
        });
        var callPool = fieldRow(pools, N_("Calls"), data.callPool, {
            type: "number", narrow: true, min: 0, max: data.poolMax,
            unit: t("of %1", data.poolMax), restart: true,
            hint: N_("Destinations kept built for call media")
        });
        var watchPool = fieldRow(pools, N_("Watching"), data.watchPool, {
            type: "number", narrow: true, min: 0, max: data.poolMax,
            unit: t("of %1", data.poolMax), restart: true,
            hint: N_("Destinations kept built for watching presence")
        });

        var routes = section(form, N_("Without I2P"));
        readOnlyRow(routes, N_("Server"),
            data.server ? data.server.host + ":" + data.server.port : "");
        if (!data.direct.length) {
            readOnlyRow(routes, N_("Facades"), "");
        }
        data.direct.forEach(function (route, index) {
            readOnlyRow(routes, index === 0 ? N_("Facades") : "",
                route.dest + " -> " + route.host + ":" + route.port);
        });
        routes.appendChild(element("p", "hint", t("Written by the panel from this deployment's"
            + " server and facades")));

        var clients = section(form, N_("Clients"));
        var publicAddress = fieldRow(clients, N_("Public address"), data.publicAddress, {
            placeholder: "https://gateway.example",
            hint: N_("Where the TLS front answers clients, with no path")
        });
        var linkRow = readOnlyRow(clients, N_("Link"), data.link,
            N_("What a client is given. It carries the secret path and the token"));
        if (data.link) {
            shareButtons(linkRow, data.link);
        }

        var facts = section(form, N_("What this gateway is"));
        readOnlyRow(facts, N_("State"), data.stateDirectory);
        readOnlyRow(facts, N_("Version"), data.version);

        function count(input, what, low, high) {
            var value = Number(input.value);
            if (!Number.isInteger(value) || value < low || value > high) {
                throw new Error(t("%1 is a whole number from %2 to %3", t(what), low, high));
            }
            return value;
        }

        var footer = saveFooter(form, N_("Written for the next start: the pools are built then"),
            function () {
                return {
                    method: "PUT",
                    path: withFleet("/api/service-settings?service=" + encodeURIComponent(name)),
                    body: {
                        i2pPrivacy: privacy(),
                        i2pTunnelQuantity: count(quantity, N_("Tunnels"), 1,
                            data.i2pTunnelQuantityMax),
                        streamPool: count(streamPool, N_("The stream pool"), 0, data.poolMax),
                        callPool: count(callPool, N_("The call pool"), 0, data.poolMax),
                        watchPool: count(watchPool, N_("The watch pool"), 0, data.poolMax),
                        publicAddress: publicAddress.value.trim()
                    }
                };
            });
        restartButton(footer, { service: name });
    }

    function renderPanelTab(form, data) {
        var who = section(form, N_("Who may sign in"));
        var admins = textareaBlock(who, N_("Administrators"), (data.admins || []).join("\n"),
            N_("52-character fingerprint"),
            N_("One fingerprint per line, as the Signature window in the client shows it. The last"
            + " one cannot be removed."));

        var consumer = data.consumer || {};
        var signing = section(form, N_("What an administrator sees before signing in"));
        var name = fieldRow(signing, N_("Name"), consumer.name, {
            limit: kConsumerNameMax, placeholder: N_("Bazarish admin panel"),
            hint: N_("Shown in the client's window before you sign a login for this panel")
        });
        var places = textareaBlock(signing, N_("Addresses"), (consumer.place || []).join("\n"),
            "http://host:port",
            N_("One per line, as you have them in the address bar when you sign in here"));
        var role = fieldRow(signing, N_("Role"), consumer.role, {
            limit: kConsumerRoleMax, placeholder: N_("Administrator"),
            hint: N_("What signing in here opens")
        });

        var serviceBlock = section(form, N_("Services this panel manages"));
        var rows = [];
        function serviceRow(fleetName, service) {
            var wrap = element("div", "service");
            var row = element("div", "service-row");
            var name = element("input", "field");
            name.type = "text";
            name.placeholder = "core";
            name.value = service ? service.name : "";
            row.appendChild(name);
            var kind = element("select", "field");
            kServiceKinds.forEach(function (known) {
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
            url.placeholder = "https://127.0.0.1:8428";
            url.value = service ? service.url : "";
            row.appendChild(url);
            var drop = element("button", "chip", t("remove"));
            row.appendChild(drop);
            wrap.appendChild(row);

            var pinRow = element("div", "service-key");
            pinRow.appendChild(element("span", "control-label", t("TLS pin")));
            var pin = element("input", "field");
            pin.type = "text";
            pin.placeholder = t("the socket pin it prints at start, 64 hex");
            pin.value = service ? (service.pin || "") : "";
            pinRow.appendChild(pin);
            wrap.appendChild(pinRow);

            var entry = { fleet: fleetName, name: name, kind: kind, url: url, pin: pin,
                dropped: false };
            drop.addEventListener("click", function () {
                var named = entry.name.value.trim() || t("this service");
                if (!window.confirm(t("Remove %1 from the panel? It is dropped when the list is"
                    + " saved.", named))) {
                    return;
                }
                entry.dropped = true;
                wrap.remove();
            });
            rows.push(entry);
            return wrap;
        }
        var fleets = data.fleets && data.fleets.length > 0
            ? data.fleets
            : [{ name: "server", services: [] }];
        fleets.forEach(function (entry) {
            var fleetName = entry.name || "server";
            if (fleets.length > 1) {
                serviceBlock.appendChild(element("h4", "block-title service-fleet", fleetName));
            }
            var head = element("div", "service-head");
            [N_("Name"), N_("Kind"), N_("Address")].forEach(function (title) {
                head.appendChild(element("span", "field-label", t(title)));
            });
            serviceBlock.appendChild(head);
            (entry.services || []).forEach(function (service) {
                serviceBlock.appendChild(serviceRow(fleetName, service));
            });
            var addRow = element("div", "controls");
            var add = element("button", "chip", t("add service"));
            add.addEventListener("click", function () {
                serviceBlock.insertBefore(serviceRow(fleetName, null), addRow);
            });
            addRow.appendChild(add);
            serviceBlock.appendChild(addRow);
        });
        serviceBlock.appendChild(element("p", "hint",
            t("Each service must list this panel's fingerprint as an operator. Its address is"
            + " the operator socket its opsListen opens. Names are unique in a deployment, which"
            + " holds one server-core and one service-node; facades and gateways may be many,"
            + " and the facades' order is the order a client tries them in.")));

        var where = section(form, N_("Where the panel listens"));
        var listen = endpointRow(where, N_("Listens on"), data.listen,
            N_("The socket this page is served on"), true);

        var facts = section(form, N_("What this panel is"));
        readOnlyRow(facts, N_("Fingerprint"), data.fingerprint,
            N_("The key the panel signs its calls with"));
        readOnlyRow(facts, N_("Config file"), data.configPath,
            N_("Where everything on this page is written back"));
        readOnlyRow(facts, N_("State"), data.stateDir);
        readOnlyRow(facts, N_("Web files"), data.assetsDir);
        readOnlyRow(facts, N_("Version"), data.version);

        var footer = saveFooter(form,
            N_("Applies now, except the listener, which the panel picks up when it restarts"),
            function () {
                var list = linesOf(admins);
                if (list.length === 0) {
                    throw new Error(t("A panel needs at least one administrator"));
                }
                var kept = rows.filter(function (entry) {
                    return !entry.dropped;
                });
                var incomplete = kept.filter(function (entry) {
                    return !entry.name.value.trim() || !entry.url.value.trim()
                        || !entry.pin.value.trim();
                });
                if (incomplete.length > 0) {
                    throw new Error(t("A service needs a name, an https URL and a key"));
                }
                var names = {};
                var singles = {};
                kept.forEach(function (entry) {
                    var named = entry.fleet + "\n" + entry.name.value.trim();
                    if (names[named]) {
                        throw new Error(t("Two services in %1 are named %2", entry.fleet,
                            entry.name.value.trim()));
                    }
                    names[named] = true;
                    if (entry.kind.value === "server-core" || entry.kind.value === "service-node") {
                        var single = entry.fleet + "\n" + entry.kind.value;
                        if (singles[single]) {
                            throw new Error(t("%1 already has a %2: a second server is a"
                                + " deployment of its own", entry.fleet, entry.kind.value));
                        }
                        singles[single] = true;
                    }
                });
                var byFleet = {};
                fleets.forEach(function (entry) {
                    byFleet[entry.name || "server"] = [];
                });
                kept.forEach(function (entry) {
                    byFleet[entry.fleet].push({
                        name: entry.name.value.trim(),
                        kind: entry.kind.value,
                        url: entry.url.value.trim(),
                        pin: entry.pin.value.trim()
                    });
                });
                return {
                    method: "PUT", path: "/api/panel",
                    after: function (answer, at) {
                        answer.descriptorErrors.forEach(function (failed) {
                            at.appendChild(notice(t("Saved, but the descriptor of %1 was not"
                                + " updated: %2", failed.fleet, failed.error), "is-error"));
                        });
                        return linkNotices(answer.gatewayLinkErrors, at)
                            || answer.descriptorErrors.length > 0;
                    },
                    body: {
                        admins: list,
                        consumer: {
                            name: name.value.trim(),
                            place: linesOf(places),
                            role: role.value.trim()
                        },
                        listen: {
                            host: listen.host.value.trim(),
                            port: portRead(listen.port, N_("The panel"))
                        },
                        fleets: fleets.map(function (entry) {
                            var fleetName = entry.name || "server";
                            return { name: fleetName, services: byFleet[fleetName] };
                        })
                    }
                };
            });
        var restart = element("button", "chip", t("restart panel"));
        restart.addEventListener("click", function () {
            restart.disabled = true;
            restart.textContent = t("restarting panel...");
            api("POST", "/api/panel/restart").then(function () {
                window.setTimeout(function () { window.location.reload(); }, kRestartWaitMs);
            }).catch(function (error) {
                restart.disabled = false;
                restart.textContent = t("restart panel");
                footer.appendChild(notice(error.message, "is-error"));
            });
        });
        footer.appendChild(restart);
    }

    var views = { monitoring: renderMonitoring, users: renderUsers, settings: renderSettings };

    var ownHashWrite = false;

    function setHash(value) {
        if (window.location.hash === value) {
            return;
        }
        ownHashWrite = true;
        window.location.hash = value;
    }

    var fleetNames = [];

    function pickFleet(name) {
        if (!name || name === fleet) {
            return;
        }
        fleet = name;
        window.localStorage.setItem("bazarish.fleet", fleet);
        renderFleetPicker(fleetNames);
    }

    function renderFleetPicker(names) {
        fleetNames = names || [];
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
        slot.appendChild(element("p", "sidebar-note", t("deployment")));
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
        views[name](parts[1], parts[2] ? decodeURIComponent(parts[2]) : undefined);
    }

    document.getElementById("languageSlot").appendChild(languagePicker(function () {
        renderFleetPicker(fleetNames);
        route();
    }));

    api("GET", "/api/services").then(function (data) {
        renderFleetPicker(data.fleets);
    }).catch(function () {
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
