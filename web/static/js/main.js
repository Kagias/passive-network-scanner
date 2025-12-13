function setupDashboard() {
  const devicesTable = document.getElementById('devices-table').getElementsByTagName('tbody')[0];
  const alertsList = document.getElementById('alerts-list');
  const scoreSpan = document.getElementById('score-value');
  // WebSocket
  const socket = io({path: "/socket.io"});
  socket.on('network_event', (payload) => {
    if (payload.devs) updateDevices(payload.devs);
  });
  socket.on('alert', (a) => {
    addAlert(a);
    fetchScore();
  });
  function fetchScore() {
    fetch('/api/security_score')
      .then(resp => resp.json())
      .then(data => { scoreSpan.textContent = data.score; });
  }
  function updateDevices(devs) {
    devicesTable.innerHTML = '';
    devs.forEach(dev => {
      devicesTable.innerHTML += `<tr>
        <td>${dev.mac}</td>
        <td>${dev.ip}</td>
        <td>${dev.vendor}</td>
        <td>${dev.hostname}</td>
        <td>${dev.first_seen}</td>
        <td>${dev.last_seen}</td>
        <td>${dev.os_guess}</td>
      </tr>`;
    });
  }
  function addAlert(al) {
    let li = document.createElement('li');
    li.innerHTML = `<b>${al.type.toUpperCase()}</b>: ${al.desc}`;
    alertsList.insertBefore(li, alertsList.firstChild);
  }
  // Initial data
  fetch('/api/devices').then(r => r.json()).then(updateDevices);
  fetch('/api/anomalies').then(r => r.json()).then(as => { as.forEach(addAlert); });
  fetchScore();
  // Traffic graph
  setupTrafficGraph();
}

function setupTrafficGraph() {
  const canvas = document.getElementById('traffic-graph');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  let data = [];
  function draw() {
    ctx.clearRect(0,0,canvas.width,canvas.height);
    ctx.strokeStyle = "#16a085";
    ctx.beginPath();
    let yScale = (canvas.height-20)/Math.max(50, ...data);
    data.forEach((v, i) => {
      let y = canvas.height-10 - v*yScale;
      if (i == 0) ctx.moveTo(i*5+10, y);
      else ctx.lineTo(i*5+10, y);
    });
    ctx.stroke();
  }
  setInterval(() => {
    fetch('/api/anomalies').then(r=>r.json()).then(as=>{
      let cnt = as.filter(a=>a.type=="burst").length;
      data.push(cnt);
      if (data.length > 100) data.shift();
      draw();
    });
  }, 1000);
}