// Bazarish project (c) 2026
(function () {
    "use strict";

    var kFeedbackMs = 1600;
    var kSignInPollMs = 2000;

    function copy(text) {
        if (navigator.clipboard && window.isSecureContext) {
            return navigator.clipboard.writeText(text);
        }
        var area = document.createElement("textarea");
        area.value = text;
        area.setAttribute("readonly", "");
        area.style.position = "fixed";
        area.style.opacity = "0";
        document.body.appendChild(area);
        area.select();
        var copied = document.execCommand("copy");
        document.body.removeChild(area);
        return copied ? Promise.resolve() : Promise.reject(new Error("the browser refused"));
    }

    function addButton(block) {
        var words = document.body.dataset;
        var button = document.createElement("button");
        button.type = "button";
        button.className = "btn btn-quiet btn-copy";
        button.textContent = words.copyDo;
        button.addEventListener("click", function () {
            copy(block.textContent).then(function () {
                button.textContent = words.copyDone;
            }, function () {
                button.textContent = words.copyByhand;
            }).then(function () {
                window.setTimeout(function () {
                    button.textContent = words.copyDo;
                }, kFeedbackMs);
            });
        });
        var after = block.closest(".copy-row") || block;
        after.parentNode.insertBefore(button, after.nextSibling);
    }

    var blocks = document.querySelectorAll("pre.copy");
    for (var i = 0; i < blocks.length; ++i) {
        addButton(blocks[i]);
    }

    function addPopup(opener) {
        var popup = document.getElementById(opener.hash.slice(1));
        if (!popup) {
            return;
        }
        function close() {
            popup.classList.remove("is-open");
            document.removeEventListener("keydown", onKey);
        }
        function onKey(event) {
            if (event.key === "Escape") {
                close();
            }
        }
        opener.addEventListener("click", function (event) {
            event.preventDefault();
            popup.classList.add("is-open");
            document.addEventListener("keydown", onKey);
        });
        popup.addEventListener("click", function (event) {
            event.preventDefault();
            close();
        });
    }

    function watchSignIn(block) {
        if (!window.fetch) {
            return;
        }
        var timer = window.setInterval(function () {
            window.fetch(block.dataset.signWait, {credentials: "same-origin"})
                .then(function (answer) {
                    return answer.ok ? answer.json() : null;
                })
                .then(function (state) {
                    if (!state || state.state === "waiting") {
                        return;
                    }
                    window.clearInterval(timer);
                    if (state.state === "signedIn") {
                        window.location.assign("/");
                        return;
                    }
                    block.querySelector("[data-sign-expired]").hidden = false;
                }, function () {
                });
        }, kSignInPollMs);
    }

    function offerSignInTabs() {
        var bar = document.querySelector("[data-signin-tabs]");
        if (!bar) {
            return;
        }
        var panes = document.querySelectorAll("[data-signin-pane]");
        var tabs = bar.querySelectorAll("[data-signin-show]");
        var show = function (name) {
            for (var p = 0; p < panes.length; ++p) {
                panes[p].hidden = panes[p].dataset.signinPane !== name;
            }
            for (var t = 0; t < tabs.length; ++t) {
                tabs[t].classList.toggle("is-on", tabs[t].dataset.signinShow === name);
            }
        };
        bar.hidden = false;
        bar.addEventListener("click", function (event) {
            if (event.target.dataset && event.target.dataset.signinShow) {
                show(event.target.dataset.signinShow);
            }
        });
        show(document.querySelector("[data-signin-pane=copy] .is-error") ? "copy" : "scan");
    }

    offerSignInTabs();

    var waiting = document.querySelectorAll("[data-sign-wait]");
    for (var k = 0; k < waiting.length; ++k) {
        watchSignIn(waiting[k]);
    }

    var openers = document.querySelectorAll("a.btn-qr");
    for (var j = 0; j < openers.length; ++j) {
        addPopup(openers[j]);
    }
})();
