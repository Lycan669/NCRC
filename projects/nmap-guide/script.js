// ========== Tabs ==========
const tabBtns = document.querySelectorAll('.tab-btn');
const tabContents = document.querySelectorAll('.tab-content');

tabBtns.forEach(btn => {
  btn.addEventListener('click', () => {
    tabBtns.forEach(b => b.classList.remove('active'));
    tabContents.forEach(c => c.classList.remove('active'));

    btn.classList.add('active');
    document.getElementById(`tab-${btn.dataset.tab}`).classList.add('active');
  });
});

// ========== Elements ==========
const els = {
  target: document.getElementById('target'),
  scanType: document.getElementById('scanType'),
  ports: document.getElementById('ports'),
  timing: document.getElementById('timing'),
  output: document.getElementById('output'),
  versionIntensity: document.getElementById('versionIntensity'),
  minRate: document.getElementById('minRate'),
  maxRetries: document.getElementById('maxRetries'),
  hostTimeout: document.getElementById('hostTimeout'),
  decoy: document.getElementById('decoy'),
  sourcePort: document.getElementById('sourcePort'),
  dataLength: document.getElementById('dataLength'),
  mtu: document.getElementById('mtu'),
  zombie: document.getElementById('zombie'),
  generatedCommand: document.getElementById('generatedCommand'),
  copyBtn: document.getElementById('copyBtn'),
  explanationContent: document.getElementById('explanationContent')
};

const checks = {
  osDetect: document.getElementById('osDetect'),
  version: document.getElementById('version'),
  scripts: document.getElementById('scripts'),
  aggressive: document.getElementById('aggressive'),
  verbose: document.getElementById('verbose'),
  openOnly: document.getElementById('openOnly'),
  reason: document.getElementById('reason'),
  packetTrace: document.getElementById('packetTrace'),
  traceroute: document.getElementById('traceroute'),
  resolveAll: document.getElementById('resolveAll'),
  noResolve: document.getElementById('noResolve'),
  privileged: document.getElementById('privileged'),
  fragment: document.getElementById('fragment'),
  badsum: document.getElementById('badsum'),
  spoofMac: document.getElementById('spoofMac'),
  dataString: document.getElementById('dataString')
};

// ========== Explanations Database ==========
const explanations = {
  '-sS': 'TCP SYN Stealth scan (default). Fast and relatively stealthy. Requires root/admin.',
  '-sT': 'TCP Connect scan. Completes the full handshake. Does not need root, but is noisier.',
  '-sU': 'UDP scan. Much slower than TCP. Essential for finding DNS, SNMP, VPN, etc.',
  '-sA': 'ACK scan. Used to map firewall rules (filtered vs unfiltered).',
  '-sN': 'Null scan (no flags). Can bypass some firewalls.',
  '-sF': 'FIN scan. Similar goal as Null scan.',
  '-sX': 'Xmas scan (FIN + PSH + URG). Classic evasion technique.',
  '-sn': 'Ping scan only (no port scan). Good for host discovery.',
  '-sI': 'Idle/Zombie scan. Completely blind scan using another host. Very advanced.',
  '-O': 'Enable OS detection.',
  '-sV': 'Probe open ports to determine service and version.',
  '-sC': 'Run default NSE scripts (safe scripts).',
  '-A': 'Aggressive scan: OS detection + version detection + script scanning + traceroute.',
  '-v': 'Increase verbosity.',
  '--open': 'Show only open ports.',
  '--reason': 'Display the reason a port is in a particular state.',
  '-f': 'Fragment packets. Tries to bypass simple firewalls and IDS.',
  '-D': 'Decoy scan. Hides your real IP among fake ones.',
  '--source-port': 'Send packets from a specific source port (useful to bypass firewall rules).',
  '--data-length': 'Append random data to packets to change their size.',
  '--mtu': 'Set custom MTU (must be multiple of 8). Used for fragmentation tricks.',
  '--badsum': 'Send packets with bad checksums (some systems react differently).',
  '--spoof-mac': 'Spoof MAC address.',
  '-T0': 'Paranoid timing (very slow, good against IDS).',
  '-T1': 'Sneaky timing.',
  '-T2': 'Polite timing.',
  '-T4': 'Aggressive timing (faster).',
  '-T5': 'Insane timing (very fast, can be unreliable).',
  '-p-': 'Scan all 65535 ports.',
  '-F': 'Fast mode (top 100 ports).',
  '--version-intensity': 'Controls how hard Nmap tries to detect versions (0-9).',
  '--min-rate': 'Force Nmap to send packets at minimum this rate.',
  '--max-retries': 'Maximum number of port scan probe retransmissions.',
  '--host-timeout': 'Give up on slow hosts after this time.',
  '--packet-trace': 'Show all packets sent and received (very verbose).',
  '--traceroute': 'Trace hop path to each host.',
  '-n': 'Never do DNS resolution.',
  '-R': 'Always resolve DNS.'
};

function buildCommand() {
  let cmd = ['nmap'];
  let explanationList = [];

  // Scan type
  if (els.scanType.value) {
    if (els.scanType.value === '-sI' && els.zombie.value.trim()) {
      cmd.push(`-sI ${els.zombie.value.trim()}`);
      explanationList.push(`<li><strong>-sI ${els.zombie.value.trim()}</strong> → Idle scan using zombie host</li>`);
    } else {
      cmd.push(els.scanType.value);
      if (explanations[els.scanType.value]) {
        explanationList.push(`<li><strong>${els.scanType.value}</strong> → ${explanations[els.scanType.value]}</li>`);
      }
    }
  }

  // Timing
  if (els.timing.value) {
    cmd.push(els.timing.value);
    explanationList.push(`<li><strong>${els.timing.value}</strong> → ${explanations[els.timing.value] || 'Timing template'}</li>`);
  }

  // Ports
  if (els.ports.value) {
    cmd.push(els.ports.value);
    explanationList.push(`<li><strong>${els.ports.value}</strong> → ${explanations[els.ports.value] || 'Port selection'}</li>`);
  }

  // Basic checks
  if (checks.osDetect.checked) {
    cmd.push('-O');
    explanationList.push(`<li><strong>-O</strong> → ${explanations['-O']}</li>`);
  }
  if (checks.version.checked) {
    cmd.push('-sV');
    explanationList.push(`<li><strong>-sV</strong> → ${explanations['-sV']}</li>`);
  }
  if (checks.scripts.checked) {
    cmd.push('-sC');
    explanationList.push(`<li><strong>-sC</strong> → ${explanations['-sC']}</li>`);
  }
  if (checks.aggressive.checked) {
    cmd.push('-A');
    explanationList.push(`<li><strong>-A</strong> → ${explanations['-A']}</li>`);
  }
  if (checks.verbose.checked) {
    cmd.push('-v');
    explanationList.push(`<li><strong>-v</strong> → ${explanations['-v']}</li>`);
  }
  if (checks.openOnly.checked) {
    cmd.push('--open');
    explanationList.push(`<li><strong>--open</strong> → ${explanations['--open']}</li>`);
  }
  if (checks.reason.checked) {
    cmd.push('--reason');
    explanationList.push(`<li><strong>--reason</strong> → ${explanations['--reason']}</li>`);
  }

  // Advanced options
  if (els.versionIntensity.value) {
    cmd.push(`--version-intensity ${els.versionIntensity.value}`);
    explanationList.push(`<li><strong>--version-intensity ${els.versionIntensity.value}</strong> → ${explanations['--version-intensity']}</li>`);
  }
  if (els.minRate.value) {
    cmd.push(`--min-rate ${els.minRate.value}`);
    explanationList.push(`<li><strong>--min-rate ${els.minRate.value}</strong> → ${explanations['--min-rate']}</li>`);
  }
  if (els.maxRetries.value) {
    cmd.push(`--max-retries ${els.maxRetries.value}`);
    explanationList.push(`<li><strong>--max-retries ${els.maxRetries.value}</strong> → ${explanations['--max-retries']}</li>`);
  }
  if (els.hostTimeout.value) {
    cmd.push(`--host-timeout ${els.hostTimeout.value}`);
    explanationList.push(`<li><strong>--host-timeout ${els.hostTimeout.value}</strong> → ${explanations['--host-timeout']}</li>`);
  }

  if (checks.packetTrace.checked) {
    cmd.push('--packet-trace');
    explanationList.push(`<li><strong>--packet-trace</strong> → ${explanations['--packet-trace']}</li>`);
  }
  if (checks.traceroute.checked) {
    cmd.push('--traceroute');
    explanationList.push(`<li><strong>--traceroute</strong> → ${explanations['--traceroute']}</li>`);
  }
  if (checks.resolveAll.checked) {
    cmd.push('-R');
    explanationList.push(`<li><strong>-R</strong> → ${explanations['-R']}</li>`);
  }
  if (checks.noResolve.checked) {
    cmd.push('-n');
    explanationList.push(`<li><strong>-n</strong> → ${explanations['-n']}</li>`);
  }
  if (checks.privileged.checked) {
    cmd.push('--privileged');
  }

  // Evasion
  if (els.decoy.value.trim()) {
    cmd.push(`-D ${els.decoy.value.trim()}`);
    explanationList.push(`<li><strong>-D ${els.decoy.value.trim()}</strong> → ${explanations['-D']}</li>`);
  }
  if (els.sourcePort.value) {
    cmd.push(`--source-port ${els.sourcePort.value}`);
    explanationList.push(`<li><strong>--source-port ${els.sourcePort.value}</strong> → ${explanations['--source-port']}</li>`);
  }
  if (els.dataLength.value) {
    cmd.push(`--data-length ${els.dataLength.value}`);
    explanationList.push(`<li><strong>--data-length ${els.dataLength.value}</strong> → ${explanations['--data-length']}</li>`);
  }
  if (els.mtu.value) {
    cmd.push(`--mtu ${els.mtu.value}`);
    explanationList.push(`<li><strong>--mtu ${els.mtu.value}</strong> → ${explanations['--mtu']}</li>`);
  }
  if (checks.fragment.checked) {
    cmd.push('-f');
    explanationList.push(`<li><strong>-f</strong> → ${explanations['-f']}</li>`);
  }
  if (checks.badsum.checked) {
    cmd.push('--badsum');
    explanationList.push(`<li><strong>--badsum</strong> → ${explanations['--badsum']}</li>`);
  }
  if (checks.spoofMac.checked) {
    cmd.push('--spoof-mac 0');
    explanationList.push(`<li><strong>--spoof-mac 0</strong> → ${explanations['--spoof-mac']}</li>`);
  }
  if (checks.dataString.checked) {
    cmd.push('--data-string "Test"');
  }

  // Output
  if (els.output.value) {
    cmd.push(els.output.value);
  }

  // Target
  const target = els.target.value.trim() || 'target';
  cmd.push(target);

  // Update command
  els.generatedCommand.textContent = cmd.join(' ');

  // Update explanation
  if (explanationList.length === 0) {
    els.explanationContent.innerHTML = `<p>Select options above to see a detailed explanation of your command.</p>`;
  } else {
    els.explanationContent.innerHTML = `
      <p>Here’s what your command does:</p>
      <ul>
        ${explanationList.join('')}
      </ul>
    `;
  }
}

// ========== Event Listeners ==========
Object.values(els).forEach(el => {
  if (el && el !== els.generatedCommand && el !== els.copyBtn && el !== els.explanationContent) {
    el.addEventListener('input', buildCommand);
    el.addEventListener('change', buildCommand);
  }
});

Object.values(checks).forEach(cb => {
  if (cb) cb.addEventListener('change', buildCommand);
});

// Copy button
els.copyBtn.addEventListener('click', () => {
  navigator.clipboard.writeText(els.generatedCommand.textContent).then(() => {
    els.copyBtn.innerHTML = '<i class="fas fa-check"></i> Copied!';
    setTimeout(() => {
      els.copyBtn.innerHTML = '<i class="fas fa-copy"></i> Copy';
    }, 2000);
  });
});

// Initial build
buildCommand();