/**
 * F17 — GUARDA DE HOST/PORTA para "status de servidor Minecraft".
 * --------------------------------------------------------------
 * Achado: o IPC `server:status` (main.js do launcher) aceitava QUALQUER
 * host[:porta] — inclusive loopback, faixas privadas e porta de servico local —
 * e o main fazia ping/consulta nesse endereco. Isso e um scanner da rede local do
 * jogador (router, NAS, cftv, dispositivos da casa) disparado por qualquer coisa
 * que consiga falar com o renderer.
 *
 * Este modulo e a implementacao CANONICA da regra (mesma usada no backend) e foi
 * escrita para ser copiada/embutida no main.js do launcher:
 *
 *   const { isAllowedMinecraftTarget } = require('./hostguard');
 *   ipcMain.handle('server:status', async (_e, address) => {
 *     const check = isAllowedMinecraftTarget(String(address || '').trim());
 *     if (!check.ok) return { online: false, error: check.error };
 *     ...
 *   });
 *
 * Regras:
 *  1) Formato estrito: host ou host:porta, 1..100 chars, [A-Za-z0-9.\-:] apenas.
 *  2) HOST: barra loopback/privado/link-local/CGNAT/multicast/reservado (IPv4 e
 *     IPv6), literais IPv4 mapeados em IPv6, e nomes locais (localhost, *.local,
 *     *.localhost, *.internal, *.lan, *.intranet, home.arpa).
 *  3) PORTA: 25565 por padrao; <1024 e a lista de portas de servico conhecidas
 *     (HTTP/HTTPS/SSH/RDP/SMB/bancos/...) sao recusadas.
 */

const DEFAULT_PORT = 25565;
const MAX_LEN = 100;

// Portas de servico conhecidas que NUNCA sao de servidor Minecraft.
const DENY_PORTS = new Set([
  1, 7, 9, 13, 19, 21, 22, 23, 25, 37, 43, 53, 67, 68, 69, 79, 80, 88, 110, 111,
  113, 119, 123, 135, 137, 138, 139, 143, 161, 162, 179, 389, 443, 445, 464, 465,
  500, 512, 513, 514, 515, 540, 548, 554, 587, 623, 631, 636, 873, 902, 989, 990,
  993, 995, 1080, 1194, 1433, 1521, 1701, 1723, 2049, 2082, 2083, 2181, 2375,
  2376, 3000, 3260, 3306, 3389, 4444, 5000, 5060, 5222, 5269, 5432, 5555, 5601,
  5672, 5900, 5901, 5984, 6000, 6379, 6443, 6667, 7001, 8000, 8006, 8080, 8081,
  8086, 8123, 8443, 8888, 9000, 9042, 9090, 9092, 9100, 9200, 9300, 9418, 10000,
  11211, 15672, 27017, 50000, 50070
]);

const LOCAL_HOSTNAMES = new Set([
  'localhost', 'ip6-localhost', 'ip6-loopback', 'broadcasthost', 'local',
  'internal', 'intranet', 'lan', 'home', 'home.arpa', 'router', 'gateway'
]);

/** IPv4 literal -> [a,b,c,d] ou null. */
function parseIpv4(host) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(String(host || ''));
  if (!m) return null;
  const partes = m.slice(1, 5).map((x) => Number(x));
  if (partes.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return null;
  return partes;
}

/** Loopback/privado/link-local/CGNAT/multicast/reservado (IPv4). */
function isPrivateIpv4(partes) {
  const [a, b, c] = partes;
  if (a === 0) return true;                       // 0.0.0.0/8
  if (a === 10) return true;                      // 10/8
  if (a === 127) return true;                     // loopback
  if (a === 169 && b === 254) return true;        // link-local
  if (a === 172 && b >= 16 && b <= 31) return true; // 172.16/12
  if (a === 192 && b === 168) return true;        // 192.168/16
  if (a === 192 && b === 0 && c === 0) return true; // 192.0.0/24
  if (a === 192 && b === 0 && c === 2) return true; // TEST-NET-1
  if (a === 198 && (b === 18 || b === 19)) return true; // benchmark
  if (a === 198 && b === 51 && c === 100) return true;  // TEST-NET-2
  if (a === 203 && b === 0 && c === 113) return true;   // TEST-NET-3
  if (a === 100 && b >= 64 && b <= 127) return true;    // CGNAT 100.64/10
  if (a >= 224) return true;                      // multicast + reservado + 255.255.255.255
  return false;
}

function isPrivateHost(host) {
  let h = String(host || '').trim().toLowerCase();
  if (!h) return true;
  if (h.startsWith('[') && h.endsWith(']')) h = h.slice(1, -1);
  // IPv6 mapeado em IPv4 (::ffff:192.168.0.1)
  const mapeado = /^::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/.exec(h);
  if (mapeado) {
    const p = parseIpv4(mapeado[1]);
    return !p || isPrivateIpv4(p);
  }
  const v4 = parseIpv4(h);
  if (v4) return isPrivateIpv4(v4);
  if (h.includes(':')) {
    // IPv6 literal
    if (h === '::' || h === '::1') return true;                 // nao especificado / loopback
    if (/^f[cd][0-9a-f]{2}:/.test(h)) return true;              // fc00::/7 unique-local
    if (/^fe[89ab][0-9a-f]:/.test(h)) return true;              // fe80::/10 link-local
    if (/^ff[0-9a-f]{2}:/.test(h)) return true;                 // ff00::/8 multicast
    return false;
  }
  if (LOCAL_HOSTNAMES.has(h)) return true;
  if (h.endsWith('.local') || h.endsWith('.localhost') || h.endsWith('.internal') ||
      h.endsWith('.intranet') || h.endsWith('.lan') || h.endsWith('.home.arpa')) return true;
  if (!h.includes('.')) return true; // nome sem ponto => resolvido por busca local (mDNS/NBNS)
  return false;
}

/**
 * Valida um alvo de status de servidor Minecraft.
 * @returns {{ok: boolean, host?: string, port?: number, error?: string}}
 */
function isAllowedMinecraftTarget(address) {
  const bruto = String(address || '').trim();
  if (!bruto) return { ok: false, error: 'empty_address' };
  if (bruto.length > MAX_LEN) return { ok: false, error: 'address_too_long' };
  if (!/^[A-Za-z0-9.\-:]+$/.test(bruto)) return { ok: false, error: 'invalid_address' };

  let host = bruto;
  let port = DEFAULT_PORT;
  // host:porta — IPv6 literal usa [..]:porta (negar e mais simples e seguro).
  const idx = bruto.lastIndexOf(':');
  if (idx !== -1) {
    const p = bruto.slice(idx + 1);
    if (!/^\d{1,5}$/.test(p)) return { ok: false, error: 'invalid_port' };
    port = Number(p);
    host = bruto.slice(0, idx);
    if (host.includes(':')) return { ok: false, error: 'ipv6_literal_not_allowed' };
  }
  if (!host) return { ok: false, error: 'missing_host' };
  if (port <= 0 || port > 65535) return { ok: false, error: 'invalid_port' };

  if (isPrivateHost(host)) return { ok: false, error: 'private_host_blocked', host };
  if (port < 1024) return { ok: false, error: 'port_not_minecraft', host, port };
  if (DENY_PORTS.has(port)) return { ok: false, error: 'port_not_minecraft', host, port };

  return { ok: true, host, port };
}

module.exports = {
  DEFAULT_PORT,
  DENY_PORTS,
  parseIpv4,
  isPrivateIpv4,
  isPrivateHost,
  isAllowedMinecraftTarget
};
