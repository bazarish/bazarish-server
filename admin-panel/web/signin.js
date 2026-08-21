// Bazarish project (c) 2026
// Small conveniences for the sign-in page. Optional: without it the page is the
// same form, it just asks for one more click.
(function () {
    "use strict";

    document.addEventListener("DOMContentLoaded", function () {
        var blob = document.getElementById("blob");
        if (!blob) {
            return;
        }

        // Copying the challenge is always followed by pasting the signature, so
        // the box is ready for it.
        document.addEventListener("click", function (event) {
            if (event.target.classList.contains("btn-copy")) {
                blob.focus();
            }
        });

        // A signed blob arrives as one paste; sign in without reaching for the
        // button.
        blob.addEventListener("keydown", function (event) {
            if (event.key === "Enter" && (event.ctrlKey || event.metaKey)) {
                blob.form.requestSubmit();
            }
        });

        // A pasted blob carries whatever whitespace the terminal added.
        blob.addEventListener("paste", function () {
            window.setTimeout(function () {
                blob.value = blob.value.trim();
            }, 0);
        });
    });
})();
