// Bazarish project (c) 2026
(function () {
    "use strict";

    document.addEventListener("DOMContentLoaded", function () {
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
