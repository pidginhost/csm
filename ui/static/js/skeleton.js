// CSM.skeleton — Loading skeleton placeholders with shimmer animation
var CSM = CSM || {};

(function() {
    // Inject CSS once
    var STYLE_ID = 'csm-skeleton-style';
    if (!document.getElementById(STYLE_ID)) {
        var style = document.createElement('style');
        style.id = STYLE_ID;
        style.textContent =
            '@keyframes csm-shimmer {' +
            '  0% { background-position: -200px 0; }' +
            '  100% { background-position: calc(200px + 100%) 0; }' +
            '}' +
            '.csm-skeleton-bar {' +
            '  height: 14px;' +
            '  border-radius: 4px;' +
            '  background: linear-gradient(90deg, #e2e8f0 0px, #f1f5f9 40px, #e2e8f0 80px);' +
            '  background-size: 200px 100%;' +
            '  animation: csm-shimmer 1.4s ease-in-out infinite;' +
            '  margin-bottom: 10px;' +
            '}' +
            '.theme-dark .csm-skeleton-bar {' +
            '  background: linear-gradient(90deg, #2d3a4e 0px, #3b4a60 40px, #2d3a4e 80px);' +
            '  background-size: 200px 100%;' +
            '}';
        document.head.appendChild(style);
    }

    /**
     * Replace element content with skeleton loading bars.
     * @param {HTMLElement} element - The element to skeletonize
     * @param {number} [barCount] - Number of bars (default 4)
     */
    CSM.skeleton = function(element, barCount) {
        if (!element) return;
        barCount = barCount || 4;
        element.setAttribute('data-csm-skeleton', '1');
        var widths = ['100%', '85%', '70%', '60%', '90%', '75%'];
        var html = '<div class="csm-skeleton-container" style="padding:12px">';
        for (var i = 0; i < barCount; i++) {
            var w = widths[i % widths.length];
            html += '<div class="csm-skeleton-bar" style="width:' + w + '"></div>';
        }
        html += '</div>';
        element.innerHTML = html;
    };

    /**
     * Remove skeleton state from an element.
     * @param {HTMLElement} element - The element to unskeleton
     */
    CSM.unskeleton = function(element) {
        if (!element) return;
        element.removeAttribute('data-csm-skeleton');
        var container = element.querySelector('.csm-skeleton-container');
        if (container) {
            container.remove();
        }
    };
})();
