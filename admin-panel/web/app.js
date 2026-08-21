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
    // A hold is the soft measure - the operator is stopping the account in order
    // to say something - so the field starts with the plainest version of it.
    var kDefaultHoldMessage = "Service for this account has been stopped.";

    var content = document.getElementById("content");
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

    function fact(label, value) {
        var row = element("li");
        row.appendChild(element("span", null, label));
        row.appendChild(element("b", null, value));
        return row;
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
        var cards = element("div", "cards");
        box.appendChild(cards);

        function load() {
            api("GET", "/api/services").then(function (data) {
                cards.innerHTML = "";
                if (!data.services.length) {
                    cards.appendChild(element("p", "muted", "No services configured."));
                }
                data.services.forEach(function (service) {
                    cards.appendChild(serviceCard(service));
                });
            }).catch(function (error) {
                cards.innerHTML = "";
                cards.appendChild(notice(error.message, "is-error"));
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
        head.appendChild(window.bazarishCopy.button("Copy key", function () {
            return user.user;
        }));
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
        facts.appendChild(fact("subscription",
            user.subscribed ? "until " + humanDate(user.notAfter) : "not redeemed yet"));
        facts.appendChild(fact("address", user.dest || "none published"));
        facts.appendChild(fact("delegation",
            isDelegated(user) ? "until " + humanDate(user.transientExpires) : "none"));
        // The mailbox and the devices live on the messaging server, so they come
        // in after the row does.
        var mailbox = fact("mailbox", "...");
        var devices = fact("devices", "...");
        facts.appendChild(mailbox);
        facts.appendChild(devices);
        api("GET", "/api/account?user=" + encodeURIComponent(user.user)).then(function (data) {
            mailbox.lastChild.textContent = humanBytes(data.usedBytes) + " of "
                + humanBytes(data.quotaBytes);
            devices.lastChild.textContent = String(data.devices);
        }).catch(function (error) {
            mailbox.lastChild.textContent = "unknown (" + error.message + ")";
            devices.lastChild.textContent = "unknown";
        });
        // A registration that never became a served account is dropped; say when,
        // so "nothing happened here" has a date attached to it.
        if (user.sweepAt) {
            facts.appendChild(fact("dropped unless finished", humanDate(user.sweepAt)));
        }
        box.appendChild(facts);

        if (user.dest) {
            controls(section(box)).appendChild(
                window.bazarishCopy.button("Copy address", function () {
                    return user.dest;
                }));
        }

        if (user.banned) {
            controls(section(box, "Ban"), "The key may register again.")
                .appendChild(actionButton("Lift the ban", "btn-quiet", function (done) {
                    api("POST", "/api/unban", { user: user.user }).then(function () {
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
            api("PUT", "/api/quota", {
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
                        api("POST", "/api/approve", { user: user.user }).then(function () {
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
                    api("POST", "/api/undelegate", {
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
                api("POST", "/api/delete", { user: user.user }).then(function () {
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
            api("POST", "/api/ban", {
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
            api("GET", query).then(function (data) {
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

    function renderSettings() {
        var box = view("settings");
        var form = element("div", "panel-box");
        box.appendChild(form);
        form.appendChild(element("p", "muted", "Loading..."));

        api("GET", "/api/settings").then(function (data) {
            form.innerHTML = "";

            var totals = element("ul", "facts");
            totals.appendChild(fact("accounts", String(data.accounts)));
            totals.appendChild(fact("allocated by quota", humanBytes(data.allocatedBytes)));
            totals.appendChild(fact("on disk", data.diskUsedBytes === null
                ? "unknown (" + data.diskError + ")"
                : humanBytes(data.diskUsedBytes)));
            form.appendChild(totals);

            var registration = section(form, "Registration");
            var modes = controls(registration,
                "Open: an account is served as soon as it registers. Moderated: it waits for you.");
            var moderated = data.requireApproval;
            var modeChips = {};
            [["open", false], ["moderated", true]].forEach(function (entry) {
                var chip = element("button", "chip" + (entry[1] === moderated ? " is-on" : ""),
                    entry[0]);
                chip.addEventListener("click", function () {
                    moderated = entry[1];
                    Object.keys(modeChips).forEach(function (key) {
                        modeChips[key].className = "chip"
                            + ((key === "moderated") === moderated ? " is-on" : "");
                    });
                });
                modeChips[entry[0]] = chip;
                modes.appendChild(chip);
            });

            var waiting = section(form, "Message to a waiting account");
            var message = element("textarea", "field");
            message.value = data.registrationMessage || "";
            message.placeholder = "How to reach you";
            controls(waiting,
                "Shown to an account that is registered but not served yet - in the portal and in"
                + " its client.").appendChild(message);

            var accounts = section(form, "New accounts");
            var storageRow = controls(accounts);
            storageRow.appendChild(element("span", "control-label", "Storage"));
            var quota = element("input", "field quota-input");
            quota.type = "number";
            quota.min = String(kMinQuotaMiB);
            quota.max = String(kMaxQuotaMiB);
            quota.step = "1";
            quota.value = String(Math.round(data.defaultQuotaBytes / kBytesPerMiB));
            storageRow.appendChild(quota);
            storageRow.appendChild(element("span", "unit", "MB"));

            var ttlRow = controls(accounts,
                "An account waiting for you, or one registered at the portal that no client ever"
                + " redeemed, is dropped after this.");
            ttlRow.appendChild(element("span", "control-label", "Keep unfinished"));
            var ttl = element("input", "field quota-input");
            ttl.type = "number";
            ttl.min = "0";
            ttl.step = "1";
            ttl.value = String(data.registrationTtlDays);
            ttlRow.appendChild(ttl);
            ttlRow.appendChild(element("span", "unit", "days (0: forever)"));

            // One button for the whole form, on a line of its own: nothing above
            // it takes effect until it is pressed.
            var footer = element("div", "form-footer");
            var save = element("button", "btn", "Save settings");
            footer.appendChild(save);
            footer.appendChild(element("span", "hint", "Applies now and is written to the node's"
                + " config, so a restart keeps it."));
            form.appendChild(footer);

            save.addEventListener("click", function () {
                var megabytes = Number(quota.value);
                if (!Number.isFinite(megabytes) || megabytes < kMinQuotaMiB
                    || megabytes > kMaxQuotaMiB) {
                    footer.appendChild(notice("Storage is a whole number of megabytes.",
                        "is-error"));
                    return;
                }
                save.disabled = true;
                api("PUT", "/api/settings", {
                    requireApproval: moderated,
                    registrationMessage: message.value.trim(),
                    registrationTtlDays: Math.max(0, Math.round(Number(ttl.value) || 0)),
                    defaultQuotaBytes: Math.round(megabytes) * kBytesPerMiB
                }).then(function () {
                    renderSettings();
                }).catch(function (error) {
                    save.disabled = false;
                    footer.appendChild(notice(error.message, "is-error"));
                });
            });
        }).catch(function (error) {
            form.innerHTML = "";
            form.appendChild(notice(error.message, "is-error"));
        });
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

    window.addEventListener("hashchange", function () {
        if (ownHashWrite) {
            ownHashWrite = false;
            return;
        }
        route();
    });
    route();
})();
