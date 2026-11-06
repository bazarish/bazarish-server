// Bazarish project (c) 2026
(function () {
    "use strict";

    var kSignInPollMs = 2000;

    function watchSignIn(block) {
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

    document.addEventListener("DOMContentLoaded", function () {
        document.getElementById("languageSlot").appendChild(languagePicker(function () {}));
        var waiting = document.querySelector("[data-sign-wait]");
        if (waiting) {
            watchSignIn(waiting);
        }
        var blob = document.getElementById("blob");
        if (!blob) {
            return;
        }

        document.addEventListener("click", function (event) {
            if (event.target.classList.contains("btn-copy")) {
                blob.focus();
            }
        });

        blob.addEventListener("keydown", function (event) {
            if (event.key === "Enter" && (event.ctrlKey || event.metaKey)) {
                blob.form.requestSubmit();
            }
        });

        blob.addEventListener("paste", function () {
            window.setTimeout(function () {
                blob.value = blob.value.trim();
            }, 0);
        });
    });
})();
