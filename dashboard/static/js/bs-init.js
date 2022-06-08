document.addEventListener('DOMContentLoaded', function() {

	var toastTriggers = document.querySelectorAll('[data-bs-toggle="toast"]');

	for (var toastTrigger of toastTriggers) {
		toastTrigger.addEventListener('click', function () {
			var toastSelector = toastTrigger.getAttribute('data-bs-target');

			if (!toastSelector) return;

			try {
				var toastEl = document.querySelector(toastSelector);

				if (!toastEl) return;

				var toast = new bootstrap.Toast(toastEl);
				toast.show();
			}
			catch(e) {
				console.error(e);
			}
		})
	}

	var charts = document.querySelectorAll('[data-bss-chart]');

	for (var chart of charts) {
		chart.chart = new Chart(chart, JSON.parse(chart.dataset.bssChart));
	}
}, false);


if (document.getElementById('memcount')) {
        const countUp = new CountUp('memcount', document.getElementById("memcount").getAttribute("countTomem"));
        if (!countUp.error) {
            countUp.start();
        } else {
            console.error(countUp.error);
        }
  }
if (document.getElementById('indcount')) {
        const countUp = new CountUp('indcount', document.getElementById("indcount").getAttribute("countToind"));
        if (!countUp.error) {
            countUp.start();
        } else {
            console.error(countUp.error);
        }
  }

	if (document.getElementById('symcount')) {
	        const countUp = new CountUp('symcount', document.getElementById("symcount").getAttribute("countTosym"));
	        if (!countUp.error) {
	            countUp.start();
	        } else {
	            console.error(countUp.error);
	        }
	  }
