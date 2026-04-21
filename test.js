const { getWazuhAgents } = require('./services/wazuhService');

getWazuhAgents()
.then(data => {
 console.log("CONNECTED TO WAZUH");
 console.log(data);
})
.catch(err => {
 console.error("FAILED");
 console.error(err.message);
});