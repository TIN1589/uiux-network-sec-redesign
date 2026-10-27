/**
 * CHART.JS INTEGRATION MODULE
 * Pure Vanilla ES6+ wrapper managing responsive SOC visual analytics
 */

let severityDonutInstance = null;
let hourlyBarInstance = null;
let sparklineInstance = null;

export function destroyOverviewCharts() {
  if (severityDonutInstance) {
    severityDonutInstance.destroy();
    severityDonutInstance = null;
  }
  if (hourlyBarInstance) {
    hourlyBarInstance.destroy();
    hourlyBarInstance = null;
  }
  if (sparklineInstance) {
    sparklineInstance.destroy();
    sparklineInstance = null;
  }
}

export function initOverviewCharts(data = null) {
  // If Chart library is not loaded yet, abort gracefully
  if (typeof Chart === 'undefined') {
    console.warn('Chart.js not loaded');
    return;
  }

  destroyOverviewCharts();

  // 1. Severity Mix Donut Chart
  const donutCanvas = document.getElementById('severityDonutChart');
  if (donutCanvas) {
    const crit = data?.crit ?? (parseInt(document.getElementById('ov-kpi-crit')?.textContent, 10) || 0);
    const high = data?.high ?? (parseInt(document.getElementById('ov-kpi-high')?.textContent, 10) || 0);
    const med = data?.med ?? (parseInt(document.getElementById('ov-kpi-med')?.textContent, 10) || 0);
    const low = data?.low ?? (parseInt(document.getElementById('ov-kpi-low')?.textContent, 10) || 0);
    const total = data?.total ?? (parseInt(document.getElementById('ov-kpi-total')?.textContent, 10) || (crit + high + med + low));

    // Update center metric text if present
    const totalEl = document.getElementById('ov-donut-total');
    if (totalEl) totalEl.textContent = total;

    // Center metric element
    const centerMetricEl = donutCanvas.parentElement?.querySelector('.donut-center-metric');

    severityDonutInstance = new Chart(donutCanvas, {
      type: 'doughnut',
      data: {
        labels: ['Critical', 'High', 'Medium', 'Low'],
        datasets: [{
          data: [crit, high, med, low],
          backgroundColor: ['#D92D20', '#DC6803', '#EAB308', '#2F6FE4'],
          borderWidth: 2,
          borderColor: '#FFFFFF',
          hoverBorderColor: '#FFFFFF',
          hoverOffset: 4
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: '76%',
        onHover: (event, activeElements) => {
          if (centerMetricEl) {
            // Fade out center metric when hovering over a slice so tooltip never clashes
            centerMetricEl.style.opacity = (activeElements && activeElements.length > 0) ? '0' : '1';
          }
        },
        plugins: {
          legend: {
            display: false
          },
          tooltip: {
            backgroundColor: '#121212',
            titleFont: { family: 'Inter', size: 12, weight: '600' },
            bodyFont: { family: 'Inter', size: 12 },
            padding: 8,
            cornerRadius: 6,
            boxPadding: 4,
            callbacks: {
              title: function(items) {
                return items[0]?.label || '';
              },
              label: function(context) {
                const val = context.raw || 0;
                const pct = total > 0 ? Math.round((val / total) * 100) : 0;
                return ` ${val} alerts (${pct}%)`;
              }
            }
          }
        },
        animation: {
          duration: 400,
          easing: 'easeOutQuart'
        }
      }
    });

    // Ensure center metric is always restored when mouse leaves canvas
    donutCanvas.onmouseleave = () => {
      if (centerMetricEl) centerMetricEl.style.opacity = '1';
    };
  }

  // 2. Alert Distribution Stacked Bar Chart (Req 6: 1h / 24h / 7d filter aware, Critical bottom -> High -> Med -> Low)
  const barCanvas = document.getElementById('hourlyBarChart');
  if (barCanvas) {
    const tabEl = document.getElementById('tab-overview');
    const win = tabEl?.getAttribute('data-window') ||
                document.querySelector('.segmented-pill-btn.active')?.textContent.trim() || '24h';

    let labels = [];
    let countSlots = 24;
    let critData = [];
    let highData = [];
    let medData = [];
    let lowData = [];

    if (win === '1h') {
      countSlots = 12; // 12 x 5-minute slots
      labels = Array.from({ length: countSlots }, (_, i) => {
        if (i === 0) return '1h ago';
        if (i === 6) return '30m';
        if (i === countSlots - 1) return 'now';
        return '';
      });
      critData = Array(countSlots).fill(0);
      highData = Array(countSlots).fill(0);
      medData = Array(countSlots).fill(0);
      lowData = Array(countSlots).fill(0);
      critData[countSlots - 1] = 1;
      critData[countSlots - 2] = 1;
      highData[countSlots - 1] = 1;
    } else if (win === '7d') {
      countSlots = 7; // 7 days
      labels = Array.from({ length: countSlots }, (_, i) => {
        if (i === 0) return '7d ago';
        if (i === 3) return '3.5d';
        if (i === countSlots - 1) return 'now';
        return '';
      });
      critData = Array(countSlots).fill(0);
      highData = Array(countSlots).fill(0);
      medData = Array(countSlots).fill(0);
      lowData = Array(countSlots).fill(0);
      critData[6] = 2;
      highData[6] = 1;
      highData[5] = 2;
      medData[5] = 1;
    } else {
      // 24h default (Req 6: Nhãn trục X: "24h ago | 12h | now")
      countSlots = 24;
      labels = Array.from({ length: countSlots }, (_, i) => {
        if (i === 0) return '24h ago';
        if (i === 12) return '12h';
        if (i === countSlots - 1) return 'now';
        return '';
      });
      critData = Array(countSlots).fill(0);
      highData = Array(countSlots).fill(0);
      medData = Array(countSlots).fill(0);
      lowData = Array(countSlots).fill(0);
      critData[23] = 2; // EVT-099, EVT-095
      highData[23] = 1; // EVT-092
      highData[21] = 1; // EVT-089
      highData[17] = 1; // EVT-084
      medData[20] = 1;  // EVT-079
    }

    // Stack order (Req 6: Critical dưới cùng, rồi High, Medium, Low)
    hourlyBarInstance = new Chart(barCanvas, {
      type: 'bar',
      data: {
        labels: labels,
        datasets: [
          {
            label: 'Critical',
            data: critData,
            backgroundColor: '#D92D20',
            borderRadius: { topLeft: 4, topRight: 4 },
            borderSkipped: false,
            barThickness: 15
          },
          {
            label: 'High',
            data: highData,
            backgroundColor: '#DC6803',
            borderRadius: { topLeft: 4, topRight: 4 },
            borderSkipped: false,
            barThickness: 15
          },
          {
            label: 'Medium',
            data: medData,
            backgroundColor: '#EAB308',
            borderRadius: { topLeft: 4, topRight: 4 },
            borderSkipped: false,
            barThickness: 15
          },
          {
            label: 'Low',
            data: lowData,
            backgroundColor: '#2F6FE4',
            borderRadius: { topLeft: 4, topRight: 4 },
            borderSkipped: false,
            barThickness: 15
          }
        ]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          x: {
            stacked: true,
            grid: { display: false },
            ticks: {
              color: '#5F5B53',
              font: { family: 'Inter', size: 11 },
              maxRotation: 0,
              autoSkip: false
            },
            border: { color: '#E7E4DC' }
          },
          y: {
            stacked: true,
            beginAtZero: true,
            max: 4,
            grid: {
              color: '#EFECE5',
              drawTicks: false
            },
            ticks: {
              stepSize: 1,
              color: '#5F5B53',
              font: { family: 'JetBrains Mono', size: 11 }
            },
            border: { display: false }
          }
        },
        plugins: {
          legend: { display: false },
          tooltip: {
            backgroundColor: '#121212',
            titleFont: { family: 'Inter', size: 12, weight: '600' },
            bodyFont: { family: 'Inter', size: 12 },
            padding: 8,
            cornerRadius: 6,
            callbacks: {
              title: function(items) {
                const idx = items[0]?.dataIndex ?? 0;
                if (win === '1h') return idx === countSlots - 1 ? 'Last 5 min' : `${(countSlots - 1 - idx) * 5}m ago`;
                if (win === '7d') return idx === countSlots - 1 ? 'Today' : `${countSlots - 1 - idx}d ago`;
                return idx === 23 ? 'Past Hour' : `${24 - idx}h ago`;
              }
            }
          }
        },
        animation: {
          duration: 350
        }
      }
    });
  }

  // 3. Mini KPI Sparkline Chart
  const sparklineCanvas = document.getElementById('kpiSparklineChart');
  if (sparklineCanvas) {
    const points = [1, 1, 2, 1, 3, 2, 4, 3, 5, 6];
    sparklineInstance = new Chart(sparklineCanvas, {
      type: 'line',
      data: {
        labels: points.map((_, i) => i),
        datasets: [{
          data: points,
          borderColor: '#121314',
          borderWidth: 2,
          pointRadius: 0,
          tension: 0.35,
          fill: false
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          x: { display: false },
          y: { display: false }
        },
        plugins: {
          legend: { display: false },
          tooltip: { enabled: false }
        },
        animation: false
      }
    });
  }
}

window.initOverviewCharts = initOverviewCharts;
window.destroyOverviewCharts = destroyOverviewCharts;
