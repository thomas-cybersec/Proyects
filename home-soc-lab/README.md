# Home SOC Lab — Wazuh + pfSense

Laboratorio personal de detección montado en VirtualBox. La idea fue construir un entorno con segmentación de red real, un SIEM aislado y telemetría enriquecida en endpoints Windows, replicando cómo se diseñaría una arquitectura defensiva en una organización chica.

**Estado actual:** infraestructura funcionando, telemetría llegando al SIEM. Los escenarios de ataque desde Kali están en el [repo de escenarios](#) (en construcción).

---

## Stack

| Componente | Versión | Rol |
|---|---|---|
| pfSense | 2.7.2 | Firewall, NAT, segmentación |
| Wazuh | 4.7.5 (All-in-One) | SIEM (Indexer + Manager + Dashboard) |
| Ubuntu Server | 22.04 LTS | Base del SIEM |
| Windows Server | 2025 | Endpoint objetivo |
| Sysmon | 15.x + config SwiftOnSecurity | Telemetría enriquecida |
| Kali Linux | 2024.x | Máquina atacante (para escenarios futuros) |

---

## Arquitectura

Cuatro zonas separadas detrás de pfSense:

```
                Internet (router de casa)
                      │
                ┌─────┴─────┐
                │  pfSense  │
                └─────┬─────┘
        ┌─────────────┼─────────────┐
        ▼             ▼             ▼
    ┌──────┐     ┌──────┐      ┌──────┐
    │ ATK  │     │ DMZ  │      │ MGMT │
    │      │     │      │      │      │
    │ Kali │     │ WinSrv      │Wazuh │
    └──────┘     └──────┘      └──────┘
```

Política base: **default deny entre zonas**. Solo se permite explícitamente el tráfico que tiene sentido para el caso de uso.

### Esquema de IPs

| Zona | CIDR | Host | IP |
|---|---|---|---|
| ATK | 192.168.10.0/24 | Kali | .10 |
| DMZ | 192.168.20.0/24 | Windows Server | .10 |
| MGMT | 192.168.30.0/24 | Wazuh | .10 |

### Tráfico permitido entre zonas

| Origen | Destino | Puertos | Para qué |
|---|---|---|---|
| ATK | DMZ | 80, 443, 3389 | Simular ataques externos |
| DMZ | MGMT | 1514, 1515 | Telemetría agente Wazuh |
| MGMT | Internet | 80, 443 | Updates del SIEM (limitado) |

Todo lo demás está bloqueado. En particular, **ATK no puede ver MGMT** — el SIEM tiene que ser invisible para el atacante.

---

## Decisiones que más me costaron entender

**Por qué el SIEM va aislado y sin internet libre.** Mi primera intuición era armarlo todo en una LAN para que sea más fácil. Después leí sobre incidentes donde los atacantes comprometen el SIEM para borrar evidencia y se me cayó la ficha. Ahora MGMT solo tiene salida controlada a 80/443 para updates, y nada más.

**Por qué las reglas van en la interfaz de origen, no de destino.** Esto me llevó tiempo. En pfSense, una regla "DMZ a MGMT en 1514" se aplica en la interfaz DMZ, no en MGMT. Es donde el tráfico **entra** al firewall. Esto se conecta con que pfSense es stateful: si la conexión la inicia el agente, las respuestas vuelven solas, sin necesidad de regla extra.

**Por qué Wazuh All-in-One y no separado.** Para un lab está bien. En producción se separa Indexer / Manager / Dashboard en nodos distintos por escalabilidad (el Indexer chupa RAM cuando crece el EPS) y por tolerancia a fallos. El Indexer normalmente se clusteriza en al menos 3 nodos.

**Por qué Sysmon con la config de SwiftOnSecurity.** Sysmon sin config no captura nada útil. La de SwiftOnSecurity es el estándar de facto en blue teams porque filtra el ruido del sistema y captura las señales que importan, alineadas implícitamente con MITRE ATT&CK. Es una de las primeras cosas que mira cualquier analista que arranca en un SOC.

---

## Lo que aprendí rompiendo cosas

**Reset completo de Wazuh.** Después de un intento de instalación previa, los daemons críticos no levantaban (`wazuh-modulesd`, `wazuh-analysisd`, `wazuh-execd`, `wazuh-remoted`). El dashboard tiraba HTTP 500. Diagnostiqué que era *configuration drift* — credenciales y certificados desincronizados entre componentes. Después de un rato debuggeando, decidí desinstalar y reinstalar limpio. Aprendí que en stacks fuertemente acoplados, es más eficiente reprovisionar que parchear. Esto es lo que en operaciones se llama *"cattle, not pets"*.

**Cloud-init y netplan peleándose.** Cada reboot me reseteaba la IP estática. Resultado de tener dos archivos de netplan (uno del instalador, otro de cloud-init) y el de cloud-init pisaba al otro. Aprendí a deshabilitar la gestión de red de cloud-init creando `/etc/cloud/cloud.cfg.d/99-disable-network-config.cfg`.

**Block private networks en pfSense WAN.** No me dejaba entrar al dashboard de Wazuh desde mi PC. La regla *"Block private networks"* viene activada por defecto en pfSense WAN para prevenir IP spoofing desde internet. En mi caso, como pfSense está doblemente NAT-eado dentro de la LAN de mi casa, esa regla bloqueaba mi propio tráfico legítimo. Tuve que deshabilitarla para el lab. **En producción esa regla es crítica y no se toca.**

**Higiene de credenciales en CLI.** En medio del debugging tipeé una contraseña en `curl -u user:pass` sin pensar. Eso queda en el bash history en texto plano. Lección: usar `curl -u admin` (sin contraseña) y dejar que la pida, o `read -s` para variables. Pequeño detalle que en producción puede ser un incidente.

---

## Estado actual

- Wazuh recibe eventos del Windows Server en tiempo real.
- Sysmon captura process create, network connection, registry value set, DNS query.
- El módulo MITRE ATT&CK ya está mapeando técnicas (T1078, T1562.001, T1059.001 entre otras) en eventos legítimos del sistema.
- Toda la cadena sobrevive un reboot completo (servicios con `enabled at boot`).

---

## Referencias que usé

- Documentación oficial de Wazuh y pfSense.
- [SwiftOnSecurity Sysmon Config](https://github.com/SwiftOnSecurity/sysmon-config) — la config que es estándar de facto.
- [MITRE ATT&CK](https://attack.mitre.org/) — para el mapeo de técnicas.

---

## Sobre este proyecto

Lo armé como parte de mi camino para meterme en blue team / SOC. Cada decisión que tomé está justificada en el documento, y los problemas que tuve están registrados en *Lessons Learned*. La idea no era seguir un tutorial sino construir algo que pueda defender en una entrevista.

Durante el desarrollo usé asistencia de IA (Claude) para debugging técnico, validación de decisiones arquitectónicas y armado de documentación. Las decisiones de diseño y la comprensión técnica son propias y verificables.

---

**Autor:** Thomas Coria
