const express = require('express');
const { exec } = require('child_process');
const bodyParser = require('body-parser');
require('dotenv').config();

const app = express();
const PORT = 3000;

// Load API secret from environment variables
const API_SECRET = process.env.API_SECRET;

// Middleware for parsing JSON
app.use(bodyParser.json());

// Middleware for API secret verification
function authenticate(req, res, next) {
  const apiSecret = req.headers['api-secret'];
  if (!apiSecret || apiSecret !== API_SECRET) {
    return res.status(403).json({ error: 'Forbidden: Invalid API secret' });
  }
  next();
}

// Helper function to execute shell commands
function executeCommand(command) {
  return new Promise((resolve, reject) => {
    exec(command, (error, stdout, stderr) => {
      if (error) {
        return reject({ error: error.message, stderr });
      }
      resolve(stdout || stderr);
    });
  });
}

// Route to add a port forwarding rule
app.post('/api/port-forward', authenticate, async (req, res) => {
  const { externalPort, targetIp, targetPort } = req.body;

  if (!externalPort || !targetIp || !targetPort) {
    return res.status(400).json({ error: 'Invalid parameters' });
  }

  try {
    const preroutingCommand = `iptables -t nat -A PREROUTING -p tcp --dport ${externalPort} -j DNAT --to-destination ${targetIp}:${targetPort}`;
    const postroutingCommand = `iptables -t nat -A POSTROUTING -j MASQUERADE`;

    await executeCommand(preroutingCommand);
    await executeCommand(postroutingCommand);

    res.json({ message: `Port forwarding added: ${externalPort} -> ${targetIp}:${targetPort}` });
  } catch (err) {
    res.status(500).json({ error: 'Failed to add port forwarding', details: err });
  }
});

// Route to list all NAT port forwarding rules
app.get('/api/port-forward', authenticate, async (req, res) => {
  try {
    const listCommand = `iptables -t nat -L PREROUTING -n -v`;
    const output = await executeCommand(listCommand);

    res.json({ message: 'NAT port forwarding rules:', rules: output });
  } catch (err) {
    res.status(500).json({ error: 'Failed to retrieve port forwarding rules', details: err });
  }
});

// Route to delete a specific port forwarding rule
app.delete('/api/port-forward', authenticate, async (req, res) => {
  const { externalPort, targetIp, targetPort } = req.body;

  if (!externalPort || !targetIp || !targetPort) {
    return res.status(400).json({ error: 'Invalid parameters' });
  }

  try {
    // Delete the specific PREROUTING rule
    const preroutingDelete = `iptables -t nat -D PREROUTING -p tcp --dport ${externalPort} -j DNAT --to-destination ${targetIp}:${targetPort}`;
    await executeCommand(preroutingDelete);

    // Check if other rules exist in PREROUTING; if not, remove MASQUERADE
    const checkRulesCommand = `iptables -t nat -L PREROUTING -n -v | grep 'DNAT --to-destination'`;
    const activeRules = await executeCommand(checkRulesCommand);

    if (!activeRules.trim()) {
      const postroutingDelete = `iptables -t nat -D POSTROUTING -j MASQUERADE`;
      await executeCommand(postroutingDelete);
    }

    res.json({ message: `Port forwarding removed: ${externalPort} -> ${targetIp}:${targetPort}` });
  } catch (err) {
    res.status(500).json({ error: 'Failed to remove port forwarding', details: err });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
