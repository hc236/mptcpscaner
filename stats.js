const results = require('./results.json')

const mptcpsites = results.filter(t=>{
    return t.Address 
    && t.PortResults.some(p => p.TCPConnectable 
            && p.MPTCPResults.some(m => !m.NoMPTCPOption && !m.WrongVersion && !m.WrongReceiverKey && !m.Timeout && m.SYNACK))
})
console.log("MPTCP Sites", mptcpsites.length);
console.log(mptcpsites.map(t => t.Host).join('\n'));
console.log(JSON.stringify(mptcpsites, null, 2));


const wrongReceiverKeys = results.filter(t=>{
    return t.Address 
    && t.PortResults.some(p => p.TCPConnectable 
            && p.MPTCPResults.some(m => !m.NoMPTCPOption && !m.WrongVersion && m.WrongReceiverKey && !m.Timeout && m.SYNACK))
})
console.log("Wrong Receiver Key Sites", wrongReceiverKeys.length);
console.log(wrongReceiverKeys.map(t => t.Host).join('\n'));


const unresolvedHosts = results.filter(t=>{
    return !t.Address
})
console.log("Unresolved Domain Hosts", unresolvedHosts.length);


const unconnectedHosts = results.filter(t=>{
    return t.Address && t.PortResults.every(p => !p.TCPConnectable )
})
console.log("Unconnected Hosts", unconnectedHosts.length);


const timeoutMPTCPHosts = results.filter(t=>{
    return t.Address 
    && (t.PortResults.filter(p => p.TCPConnectable && p.Port == 80)
                    .every(p=> p.MPTCPResults.every(m => m.Timeout))
        || t.PortResults.filter(p => p.TCPConnectable && p.Port == 443)
        .every(p=> p.MPTCPResults.every(m => m.Timeout)))
})

const timeoutMPTCPHosts80 = results.filter(t=>{
    return t.Address 
    && t.PortResults.filter(p => p.TCPConnectable && p.Port == 80)
                    .every(p=> p.MPTCPResults.every(m => m.Timeout))
                    
})

const timeoutMPTCPHosts443 = results.filter(t=>{
    return t.Address 
    && t.PortResults.filter(p => p.TCPConnectable && p.Port == 443)
                    .every(p=> p.MPTCPResults.every(m => m.Timeout))
})

const timeoutMPTCPHostsBoth = results.filter(t=>{
    return t.Address 
    && (t.PortResults.filter(p => p.TCPConnectable && p.Port == 80)
                    .every(p=> p.MPTCPResults.every(m => m.Timeout))
        && t.PortResults.filter(p => p.TCPConnectable && p.Port == 443)
        .every(p=> p.MPTCPResults.every(m => m.Timeout)))
})
console.log("Timeout MPTCP", timeoutMPTCPHosts.length, 
"Port80", timeoutMPTCPHosts80.length, 
"Port443", timeoutMPTCPHosts443.length,
"Both", timeoutMPTCPHostsBoth.length);