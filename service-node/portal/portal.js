// Bazarish project (c) 2026
// Optional. The portal works without it: every block below is already
// selectable by hand, and this only adds a button for the browsers that run
// scripts. Nothing here talks to the network.
(function () {
    "use strict";

    // How long the button says what it did before going back to its name.
    var kFeedbackMs = 1600;

    function copy(text) {
        if (navigator.clipboard && window.isSecureContext) {
            return navigator.clipboard.writeText(text);
        }
        // Plain HTTP has no clipboard API, so fall back to a selection the old
        // command can take.
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
        var button = document.createElement("button");
        button.type = "button";
        button.className = "btn btn-quiet btn-copy";
        button.textContent = "Copy";
        button.addEventListener("click", function () {
            copy(block.textContent).then(function () {
                button.textContent = "Copied";
            }, function () {
                // Say what happened: a button that silently does nothing is
                // worse than no button.
                button.textContent = "Select it and copy";
            }).then(function () {
                window.setTimeout(function () {
                    button.textContent = "Copy";
                }, kFeedbackMs);
            });
        });
        block.parentNode.insertBefore(button, block.nextSibling);
    }

    var blocks = document.querySelectorAll("pre.copy");
    for (var i = 0; i < blocks.length; ++i) {
        addButton(blocks[i]);
    }
})();
