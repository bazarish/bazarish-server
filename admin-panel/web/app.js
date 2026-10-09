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
    var kDefaultHoldMessage = "Service for this account has been stopped.";

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
        row.appendChild(element("span", "fact-label", label));
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

    var kThousand = 1000;
    var kMillion = 1000 * kThousand;

    function accountsCounted(total) {
        return total + (total === 1 ? " account" : " accounts");
    }

    function humanCount(n) {
        var value = Number(n) || 0;
        if (value < kThousand) {
            return String(value);
        }
        return value < kMillion ? (value / kThousand).toFixed(1) + "k"
            : (value / kMillion).toFixed(1) + "M";
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
            if (service.kind === "facade") {
                facts.appendChild(fact("requests", humanCount(service.requestsLastMinute)
                    + "/min  " + humanCount(service.requestsLastHour)
                    + "/h  " + humanCount(service.requestsLastDay) + "/day"));
                facts.appendChild(fact("in flight", String(service.inFlight)));
            }
            if (service.kind === "gateway") {
                facts.appendChild(fact("sessions", humanCount(service.sessions)));
                facts.appendChild(fact("destinations", humanCount(service.destinations)));
                facts.appendChild(fact("streams", humanCount(service.streams)));
                facts.appendChild(fact("refused", humanCount(service.refused)));
                facts.appendChild(fact("i2pd", service.router || "-"));
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
                    groups.appendChild(element("p", "muted",
                        "No services yet. Add them in Settings, Panel."));
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
            tags.appendChild(element("span", "tag is-pending", "lapsed"));
        } else {
            tags.appendChild(element("span", "tag", "no address"));
        }
        return tags;
    }

    function section(box, title) {
        var block = element("section", "block");
        if (title) {
            block.appendChild(element("h3", "block-title", title));
        }
        box.appendChild(block);
        return block;
    }

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
        quotaRow.appendChild(element("span", "unit", "MiB"));
        quotaRow.appendChild(actionButton("Save", "btn-quiet", function (done) {
            var megabytes = Number(quota.value);
            if (!Number.isFinite(megabytes) || megabytes < kMinQuotaMiB
                || megabytes > kMaxQuotaMiB) {
                done();
                onError(new Error("A quota is a whole number of MiB."));
                return;
            }
            api("PUT", withFleet("/api/quota"), {
                user: user.user,
                quotaBytes: Math.round(megabytes) * kBytesPerMiB
            }).then(function () {
                onChanged("Quota set to " + Math.round(megabytes) + " MiB.");
            }).catch(function (error) {
                done();
                onError(error);
            });
        }));

        var onHold = user.approval === "pending" && Boolean(user.holdMessage);
        if (user.approval === "pending") {
            controls(section(box, onHold ? "Back into service" : "Approval"),
                onHold ? "The client republishes the address within a minute."
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
                ? "Replaces the line its owner reads. The account stays out of service."
                : "Revokes the address. The account waits for approval again and its owner reads"
                    + " this line.");
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
                "Registered at the portal, not redeemed by a client yet. Nothing to approve."));
        }

        var removeBlock = section(box, "Delete");
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

        var banRow = controls(section(box, "Ban"),
            "Deletes the account. This key does not register here again.");
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
        ["all", "pending", "approved", "banned"].forEach(function (name) {
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
            keys.appendChild(element("span", "row-dest", user.dest || "no address published"));
            row.appendChild(keys);
            row.appendChild(stateTags(user));
            row.appendChild(element("span", "row-quota",
                Math.round(user.quotaBytes / kBytesPerMiB) + " MiB"));
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
                    ? accountsCounted(total)
                    : offset + " of " + accountsCounted(total);
                more.textContent = exhausted ? "" : "Scroll for more";
                if (!rows.children.length) {
                    rows.appendChild(element("p", "muted", "Nothing here."));
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
        { id: "registration", label: "Registration" },
        { id: "portal", label: "Portal" },
        { id: "addresses", label: "Addresses" },
        { id: "accounts", label: "Accounts" },
        { id: "server", label: "Server" },
        { id: "facade", label: "Facade" },
        { id: "panel", label: "Panel" }
    ];
    var kLogLevels = ["error", "warn", "info", "debug"];
    var kServiceKinds = ["server-core", "service-node", "facade", "gateway"];
    var kPrivacyLevels = ["minimal", "middle", "max"];
    var kRestartWaitMs = 10000;
    var settingsTab = kSettingsTabs[0].id;

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
        if (options.max !== undefined) {
            input.max = String(options.max);
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

    function readOnlyRow(block, label, value, hint) {
        var row = controls(block, hint);
        row.appendChild(element("span", "control-label", label));
        var shown = value === null || value === undefined || value === "" ? "not set" : String(value);
        row.appendChild(element("span", "readonly" + (shown === "not set" ? " is-unset" : ""), shown));
        return row;
    }

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
        port.min = String(kMinPort);
        port.max = String(kMaxPort);
        port.value = value.port ? String(value.port) : "";
        row.appendChild(port);
        if (restart) {
            row.appendChild(element("span", "badge-restart", "restart"));
        }
        return { host: host, port: port };
    }

    function chipRow(block, label, hint, choices, current, spec) {
        var options = spec || {};
        var row = controls(block, hint);
        if (label) {
            row.appendChild(element("span", "control-label", label));
        }
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
                if (options.onPick) {
                    options.onPick(picked);
                }
            });
            chips[String(choice.value)] = chip;
            row.appendChild(chip);
        });
        if (options.restart) {
            row.appendChild(element("span", "badge-restart", "restart"));
        }
        return function () { return picked; };
    }

    function textareaBlock(block, label, value, placeholder, hint, tall) {
        block.appendChild(element("p", "field-label", label));
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

    function restartButton(footer, kind) {
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
        if (!Number.isInteger(port) || port < kMinPort || port > kMaxPort) {
            throw new Error(what + " needs a port between " + kMinPort + " and " + kMaxPort + ".");
        }
        return port;
    }

    function renderSettings(wanted) {
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
        var says;
        var how = section(form, "Who gets an account");
        var moderated = chipRow(how, "",
            "Open: an account is served as soon as it registers. Moderated: it waits for you.",
            [{ value: false, label: "open" }, { value: true, label: "moderated" }],
            Boolean(data.requireApproval),
            { onPick: function (picked) { says.hidden = !picked; } });

        says = section(form, "What people are told");
        says.hidden = !data.requireApproval;
        var portalMessage = textareaBlock(says, "Before registering", data.portalMessage,
            "What this server is, and what registering here means",
            "Shown by a client that reaches this server without an account here.");
        var waiting = textareaBlock(says, "While waiting", data.registrationMessage,
            "How to reach you",
            "Shown to an account that is registered and not served yet.");

        var footer = saveFooter(form,
            "Applies now and is written to the node's config, so a restart keeps it.",
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
        restartButton(footer, "service-node");
    }

    function renderPortalTab(form, data) {
        var consumer = data.loginConsumer || {};
        var signing = section(form, "What a user sees before signing in");
        var name = fieldRow(signing, "Name", consumer.name, {
            limit: kConsumerNameMax, placeholder: "The name of this site",
            hint: "Shown in the client's window before a user signs a login for this portal."
        });
        var places = textareaBlock(signing, "Addresses", (consumer.place || []).join("\n"),
            "http://host:port",
            "One per line. A user compares these with their address bar before signing.");
        var role = fieldRow(signing, "Role", consumer.role, {
            limit: kConsumerRoleMax, placeholder: "Account owner",
            hint: "Whose account the signature is for."
        });

        var reach = section(form, "Where the portal answers");
        var links = textareaBlock(reach, "Links", (data.portalLinks || []).join("\n"),
            "https://host:port",
            "Shown by a client to a person who has no account here. One per line.");
        var listen = endpointRow(reach, "Listens on", data.portalListen,
            "The socket the portal binds. It serves the reseed too.", true);

        var footer = saveFooter(form,
            "The words apply to the next challenge; the listener needs a restart.",
            function () {
                var signer = {
                    name: name.value.trim(), place: linesOf(places), role: role.value.trim()
                };
                var missing = Object.keys(signer).filter(function (key) {
                    return signer[key].length === 0;
                });
                if (missing.length > 0) {
                    throw new Error("A sign-in challenge needs its " + missing[0] + ".");
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
        restartButton(footer, "service-node");
    }

    function renderAddressesTab(form, data) {
        var reach = section(form, "How clients reach this server");
        var facades = textareaBlock(reach, "Facades", (data.facades || []).join("\n"),
            "http://<b32>.b32.i2p/<base path>",
            "One per line, in the order a client tries them. Every one is a .b32.i2p address.",
            true);
        var reseeds = textareaBlock(reach, "Reseeds", (data.reseeds || []).join("\n"),
            "https://host:port/<base path>",
            "One per line. A client with no I2P router fetches the network database here.",
            true);
        readOnlyRow(reach, "Descriptor", data.descriptor,
            "Built from both lists. This is what a user pastes into their client.");

        var wiring = section(form, "This node's own wiring");
        var listen = endpointRow(wiring, "Operator API", data.listen,
            "Where the node answers the panel. Not a public address.", true);
        var messaging = endpointRow(wiring, "Messaging server", data.messaging,
            "The server-core this node is bound to: where it pushes quotas and reads mailboxes.",
            true);
        var level = chipRow(wiring, "Log level", "Applies at once.",
            kLogLevels.map(function (name) { return { value: name, label: name }; }),
            data.logLevel || "info");

        var footer = saveFooter(form,
            "Addresses and the log level apply now; the sockets need a restart.",
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
        restartButton(footer, "service-node");
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
            type: "number", narrow: true, min: kMinQuotaMiB, max: kMaxQuotaMiB, unit: "MiB",
            hint: "The mailbox a registration is granted."
        });
        var ttl = fieldRow(accounts, "Delete when idle for", data.idleDeleteDays, {
            type: "number", narrow: true, min: 0, unit: "days (0: forever)",
            hint: "An account that delegates no address for this long is deleted."
        });

        saveFooter(form, "Applies now and is written to the node's config, so a restart keeps it.",
            function () {
                var megabytes = Number(quota.value);
                if (!Number.isFinite(megabytes) || megabytes < kMinQuotaMiB
                    || megabytes > kMaxQuotaMiB) {
                    throw new Error("Storage is a whole number of MiB.");
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
        var level = chipRow(talk, "Log level", "Applies at once.",
            kLogLevels.map(function (name) { return { value: name, label: name }; }),
            data.logLevel || "info");
        var i2pLog = chipRow(talk, "i2pd log",
            "libi2pd's own lines in this server's log. Loud. Applies at once.",
            [{ value: false, label: "off" }, { value: true, label: "on" }],
            Boolean(data.i2pLog));

        var i2p = section(form, "How this server sits on I2P");
        var privacy = chipRow(i2p, "Privacy",
            "Hops each tunnel takes: minimal is one, max is three.",
            kPrivacyLevels.map(function (name) { return { value: name, label: name }; }),
            data.i2pPrivacy || "max", { restart: true });
        var tunnels = fieldRow(i2p, "Tunnels per address", data.i2pTunnelQuantity, {
            type: "number", narrow: true, min: 1, max: data.i2pTunnelQuantityMax,
            unit: "of " + data.i2pTunnelQuantityMax, restart: true,
            hint: "Parallel tunnels per destination. Lower it on a thin uplink."
        });

        var limits = section(form, "What it accepts");
        var rate = fieldRow(limits, "Inbound per peer", data.federationRateLimit, {
            type: "number", narrow: true, min: 1, unit: "deliveries / minute", restart: true,
            hint: "Per peer destination. It bounds one sender, not the server."
        });
        var wiring = section(form, "Where it stands");
        var listen = endpointRow(wiring, "Listens on", data.listen,
            "The private channel the facade and the node reach it on. Never public.", true);
        var node = fieldRow(wiring, "Service node", data.serviceNode, {
            placeholder: "http://127.0.0.1:8421", restart: true,
            hint: "The node this server reports to."
        });
        readOnlyRow(wiring, "Fingerprint", data.fingerprint,
            "This server's identity. Clients pin it.");
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
                        listen: {
                            host: listen.host.value.trim(),
                            port: portRead(listen.port, "The messaging server")
                        },
                        serviceNode: node.value.trim()
                    }
                };
            });
        restartButton(footer, "server-core");
    }

    function renderFacadeTab(form, data) {
        var secret = section(form, "The secret prefix");
        var basePath = fieldRow(secret, "Base path", data.basePath, {
            placeholder: "/8f1818f3/0966179fb196", restart: true,
            hint: "The whole facade API lives under this prefix; nothing outside it answers."
                + " Changing it invalidates every descriptor already handed out."
        });

        var talk = section(form, "What the facade says");
        var level = chipRow(talk, "Log level", "Applies at once.",
            kLogLevels.map(function (name) { return { value: name, label: name }; }),
            data.logLevel || "info");

        var sockets = section(form, "Sockets");
        var listen = endpointRow(sockets, "API", data.listen,
            "What its own I2P addresses relay to, under the base path above. Keep it on"
            + " loopback.", true);
        var ops = endpointRow(sockets, "Operator", data.opsListen,
            "The private socket this page is talking to: health, settings, restart. Never"
            + " published to clients.", true);
        var direct = endpointRow(sockets, "Direct", data.directListen,
            "What the I2P addresses serve, over TLS, for a gateway given a route here. Empty:"
            + " not opened.", true);

        var backends = section(form, "What it forwards to");
        var messaging = endpointRow(backends, "Messaging server", data.messaging,
            "Its only backend. The sealed client tunnel and the server card go here.", true);

        var i2p = section(form, "Its I2P side");
        var enabled = chipRow(i2p, "I2P",
            "Off: the facade publishes no address, and no client can reach it.",
            [{ value: true, label: "on" }, { value: false, label: "off" }],
            data.i2pEnabled !== false, { restart: true });
        var destinations = fieldRow(i2p, "Destinations", data.i2pDestinations, {
            type: "number", narrow: true, min: 1, max: data.i2pDestinationsMax,
            unit: "of " + data.i2pDestinationsMax, restart: true,
            hint: "More than one spreads client traffic across separate addresses."
        });
        var privacy = chipRow(i2p, "Privacy", "Hops each tunnel takes: minimal is one, max is"
            + " three.",
            kPrivacyLevels.map(function (name) { return { value: name, label: name }; }),
            data.i2pPrivacy || "max", { restart: true });
        var tunnels = fieldRow(i2p, "Tunnels per address", data.i2pTunnelQuantity, {
            type: "number", narrow: true, min: 1, max: data.i2pTunnelQuantityMax,
            unit: "of " + data.i2pTunnelQuantityMax, restart: true
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
                var request = {
                    method: "PUT",
                    path: withFleet("/api/service-settings?kind=facade"),
                    body: {
                        basePath: path,
                        logLevel: level(),
                        listen: {
                            host: listen.host.value.trim(),
                            port: portRead(listen.port, "The API listener")
                        },
                        opsListen: {
                            host: ops.host.value.trim(),
                            port: portRead(ops.port, "The operator listener")
                        },
                        messaging: {
                            host: messaging.host.value.trim(),
                            port: portRead(messaging.port, "The messaging server")
                        },
                        i2pEnabled: enabled(),
                        i2pDestinations: Math.round(Number(destinations.value) || 0),
                        i2pPrivacy: privacy(),
                        i2pTunnelQuantity: Math.round(Number(tunnels.value) || 0)
                    }
                };
                if (direct.host.value.trim() !== "" || direct.port.value !== "") {
                    request.body.directListen = {
                        host: direct.host.value.trim(),
                        port: portRead(direct.port, "The direct listener")
                    };
                }
                return request;
            });
        restartButton(footer, "facade");
    }

    function renderPanelTab(form, data) {
        var who = section(form, "Who may sign in");
        var admins = textareaBlock(who, "Administrators", (data.admins || []).join("\n"),
            "52-character fingerprint",
            "One fingerprint per line, as the Signature window in the client shows it. The last"
            + " one cannot be removed.");

        var consumer = data.consumer || {};
        var signing = section(form, "What an administrator sees before signing in");
        var name = fieldRow(signing, "Name", consumer.name, {
            limit: kConsumerNameMax, placeholder: "Bazarish admin panel",
            hint: "Shown in the client's window before you sign a login for this panel."
        });
        var places = textareaBlock(signing, "Addresses", (consumer.place || []).join("\n"),
            "http://host:port",
            "One per line, as you have them in the address bar when you sign in here.");
        var role = fieldRow(signing, "Role", consumer.role, {
            limit: kConsumerRoleMax, placeholder: "Administrator",
            hint: "What signing in here opens."
        });

        var serviceBlock = section(form, "Services this panel manages");
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
            var drop = element("button", "chip", "remove");
            row.appendChild(drop);
            wrap.appendChild(row);

            var pinRow = element("div", "service-key");
            pinRow.appendChild(element("span", "control-label", "Key"));
            var pin = element("input", "field");
            pin.type = "text";
            pin.placeholder = "the pin this service prints at startup";
            pin.value = service ? (service.pin || "") : "";
            pinRow.appendChild(pin);
            wrap.appendChild(pinRow);

            var entry = { fleet: fleetName, name: name, kind: kind, url: url, pin: pin,
                dropped: false };
            drop.addEventListener("click", function () {
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
            ["Name", "Kind", "Address"].forEach(function (title) {
                head.appendChild(element("span", "field-label", title));
            });
            serviceBlock.appendChild(head);
            (entry.services || []).forEach(function (service) {
                serviceBlock.appendChild(serviceRow(fleetName, service));
            });
            var addRow = element("div", "controls");
            var add = element("button", "chip", "add service");
            add.addEventListener("click", function () {
                serviceBlock.insertBefore(serviceRow(fleetName, null), addRow);
            });
            addRow.appendChild(add);
            serviceBlock.appendChild(addRow);
        });
        serviceBlock.appendChild(element("p", "hint",
            "Each service must list this panel's fingerprint as an operator. Its address is"
            + " the operator socket its opsListen opens."));

        var where = section(form, "Where the panel listens");
        var listen = endpointRow(where, "Listens on", data.listen,
            "The socket this page is served on.", true);

        var facts = section(form, "What this panel is");
        readOnlyRow(facts, "Fingerprint", data.fingerprint,
            "The key the panel signs its calls with.");
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
                var kept = rows.filter(function (entry) {
                    return !entry.dropped;
                });
                var incomplete = kept.filter(function (entry) {
                    return !entry.name.value.trim() || !entry.url.value.trim()
                        || !entry.pin.value.trim();
                });
                if (incomplete.length > 0) {
                    throw new Error("A service needs a name, an https URL and a key.");
                }
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
                    body: {
                        admins: list,
                        consumer: {
                            name: name.value.trim(),
                            place: linesOf(places),
                            role: role.value.trim()
                        },
                        listen: {
                            host: listen.host.value.trim(),
                            port: portRead(listen.port, "The panel")
                        },
                        fleets: fleets.map(function (entry) {
                            var fleetName = entry.name || "server";
                            return { name: fleetName, services: byFleet[fleetName] };
                        })
                    }
                };
            });
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

    var views = { monitoring: renderMonitoring, users: renderUsers, settings: renderSettings };

    var ownHashWrite = false;

    function setHash(value) {
        if (window.location.hash === value) {
            return;
        }
        ownHashWrite = true;
        window.location.hash = value;
    }

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
