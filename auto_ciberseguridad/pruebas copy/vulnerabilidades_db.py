# Base de datos de vulnerabilidades conocidas
# Formato: {servicio: {versión: [(CVE-ID, descripción, puntuación CVSS)]}}
VULN_DATABASE = {
    "OpenSSH": {
        "7.2p2": [
            ("CVE-2016-6515", "Vulnerabilidad DoS por uso excesivo de CPU", 7.5),
            ("CVE-2016-8858", "Vulnerabilidad de buffer overflow", 7.8)
        ],
        "7.3": [
            ("CVE-2017-15906", "Vulnerabilidad en manejo de permisos", 5.0)
        ],
        "8.0": [
            ("CVE-2019-6111", "Vulnerabilidad de sobreescritura de archivo", 5.9)
        ],
        "8.1p1": [
            ("CVE-2020-14145", "Posible fuga de información de conexión inicial", 4.3)
        ],
        "8.2p1": [
            ("CVE-2020-15778", "Vulnerabilidad de ejecución de comandos", 6.8),
            ("CVE-2021-28041", "Desbordamiento de enteros en la verificación del límite", 4.6)
        ],
        "8.3p1": [
            ("CVE-2020-15778", "Vulnerabilidad de ejecución de comandos", 6.8),
            ("CVE-2021-41617", "Problema de autenticación en sshd", 7.5)
        ],
        "8.4p1": [
            ("CVE-2021-41617", "Problema de autenticación en sshd", 7.5),
            ("CVE-2021-36368", "Vulnerabilidad en la gestión de memoria", 5.9)
        ],
        "8.5p1": [
            ("CVE-2021-36368", "Vulnerabilidad en la gestión de memoria", 5.9)
        ],
        "8.6p1": [
            ("CVE-2021-36368", "Vulnerabilidad en la gestión de memoria", 5.9),
            ("CVE-2021-28041", "Desbordamiento de enteros en la verificación del límite", 4.6)
        ],
        "8.7p1": [
            ("CVE-2021-41617", "Problema de autenticación en sshd", 7.5)
        ],
        "8.8p1": [
            ("CVE-2022-2068", "Vulnerabilidad en OpenSSL relacionada con SSH", 7.5)
        ],
        "9.0p1": [
            ("CVE-2023-25136", "Vulnerabilidad en la gestión de canales SFTP", 5.3),
            ("CVE-2023-38408", "Información confidencial divulgada en logs", 4.7)
        ],
        "9.1p1": [
            ("CVE-2023-25136", "Vulnerabilidad en la gestión de canales SFTP", 5.3),
            ("CVE-2023-38408", "Información confidencial divulgada en logs", 4.7)
        ],
        "9.2p1": [
            ("CVE-2023-38408", "Información confidencial divulgada en logs", 4.7)
        ],
        "9.3p1": [
            ("CVE-2023-48795", "Vulnerabilidad de downgrade en el protocolo (Terrapin)", 5.9),
            ("CVE-2024-3094", "Vulnerabilidad de denegación de servicio en la negociación de algoritmos", 6.5)
        ],
        "9.4p1": [
            ("CVE-2023-48795", "Vulnerabilidad de downgrade en el protocolo (Terrapin)", 5.9)
        ],
        "9.5p1": [
            ("CVE-2023-48795", "Vulnerabilidad de downgrade en el protocolo (Terrapin)", 5.9)
        ],
        "9.6": [
            ("CVE-2024-6387", "Vulnerabilidad de autenticación (SpectreSSH)", 7.8),
            ("CVE-2024-8618", "Desbordamiento de buffer en el procesamiento de paquetes", 8.1),
            ("CVE-2024-3094", "Vulnerabilidad de denegación de servicio en la negociación de algoritmos", 6.5)
        ]
    },
    "Apache": {
        "2.4.6": [
            ("CVE-2017-9798", "Optionsbleed - fuga de información", 5.0),
            ("CVE-2016-8743", "Vulnerabilidad de respuesta dividida HTTP", 7.5)
        ],
        "2.4.10": [
            ("CVE-2016-4975", "Vulnerabilidad en uso de memoria", 6.8)
        ],
        "2.4.39": [
            ("CVE-2019-10082", "Vulnerabilidad de DoS en mod_http2", 7.5)
        ],
        "2.4.49": [
            ("CVE-2021-41773", "Vulnerabilidad de traversal de directorios", 9.8),
            ("CVE-2021-42013", "Vulnerabilidad de ejecución de código remoto", 9.8)
        ],
        "2.4.50": [
            ("CVE-2021-42013", "Vulnerabilidad de ejecución de código remoto", 9.8)
        ],
        "2.4.51": [
            ("CVE-2022-22721", "Posible corrupción de memoria en HTTP/2", 7.5)
        ],
        "2.4.52": [
            ("CVE-2022-22721", "Posible corrupción de memoria en HTTP/2", 7.5),
            ("CVE-2022-22720", "Vulnerabilidad de denegación de servicio", 7.5)
        ],
        "2.4.53": [
            ("CVE-2022-26377", "Vulnerabilidad de exposición de información", 5.3),
            ("CVE-2022-28330", "Vulnerabilidad de denegación de servicio en mod_lua", 6.5)
        ],
        "2.4.54": [
            ("CVE-2022-28330", "Vulnerabilidad de denegación de servicio en mod_lua", 6.5),
            ("CVE-2022-29404", "Vulnerabilidad en la validación de entrada", 7.5)
        ],
        "2.4.55": [
            ("CVE-2023-25690", "Vulnerabilidad de request smuggling en mod_proxy", 9.0),
            ("CVE-2023-27522", "Vulnerabilidad de denegación de servicio", 7.5)
        ],
        "2.4.56": [
            ("CVE-2023-31122", "Vulnerabilidad en mod_proxy_uwsgi", 7.5)
        ],
        "2.4.57": [
            ("CVE-2023-45802", "Vulnerabilidad de denegación de servicio en el procesamiento HTTP/2", 7.5),
            ("CVE-2023-43622", "Problemas de seguridad con mod_proxy y HTTP/1.1", 5.3)
        ],
        "2.4.58": [
            ("CVE-2023-45801", "Vulnerabilidad de escritura fuera de límites en mod_dav", 8.2),
            ("CVE-2023-47761", "Divulgación de información sensible en entornos de servidores virtuales", 5.3),
            ("CVE-2023-25690", "Vulnerabilidad de HTTP Request Smuggling en mod_proxy", 7.1),
            ("CVE-2023-31122", "Vulnerabilidad en mod_proxy_uwsgi", 7.5)
        ],
        "2.4.59": [
            ("CVE-2024-25629", "Vulnerabilidad de DoS en el manejo de conexiones HTTP/2", 6.5)
        ]
    },
    "nginx": {
        "1.16.0": [
            ("CVE-2019-9511", "HTTP/2 DoS vulnerabilidad", 7.5)
        ],
        "1.14.0": [
            ("CVE-2018-16845", "Problema de corrupción de memoria", 8.1)
        ],
        "1.18.0": [
            ("CVE-2020-11724", "Vulnerabilidad de desbordamiento de entero", 7.5),
            ("CVE-2021-23017", "Vulnerabilidad de resolución de ruta", 9.4)
        ],
        "1.20.0": [
            ("CVE-2021-33193", "Vulnerabilidad de divulgación de información", 5.3)
        ],
        "1.22.0": [
            ("CVE-2022-41741", "Vulnerabilidad de DoS por limitación de conexiones", 6.5),
            ("CVE-2022-41742", "Vulnerabilidad en el procesamiento HTTP/2", 7.5)
        ],
        "1.24.0": [
            ("CVE-2023-44487", "Vulnerabilidad de HTTP/2 rapid reset", 7.5)
        ],
        "1.25.0": [
            ("CVE-2023-44487", "Vulnerabilidad de HTTP/2 rapid reset", 7.5)
        ]
    },
    "ProFTPD": {
        "1.3.5": [
            ("CVE-2015-3306", "Vulnerabilidad de ejecución remota de código", 9.8)
        ],
        "1.3.6": [
            ("CVE-2019-12815", "Vulnerabilidad de buffer overflow", 8.8),
            ("CVE-2019-18217", "Acceso fuera de límites de buffer", 7.5)
        ],
        "1.3.7rc2": [
            ("CVE-2020-9272", "Vulnerabilidad de ejecución remota de código", 9.8),
            ("CVE-2020-9273", "Uso después de liberar en el manejo de directorio", 7.5)
        ],
        "1.3.7": [
            ("CVE-2021-46854", "Vulnerabilidad de bypass de autenticación", 9.8)
        ]
    },
    "MySQL": {
        "5.7": [
            ("CVE-2018-2696", "Vulnerabilidad de elevación de privilegios", 8.0),
            ("CVE-2020-2760", "Vulnerabilidad de denegación de servicio", 6.5),
            ("CVE-2021-2307", "Vulnerabilidad en la función UDF", 7.2),
            ("CVE-2022-21417", "Bypass de autenticación", 9.8)
        ],
        "8.0": [
            ("CVE-2020-14539", "Vulnerabilidad en la gestión de privilegios", 7.2),
            ("CVE-2021-2372", "Vulnerabilidad de escalada de privilegios", 8.8),
            ("CVE-2022-21417", "Bypass de autenticación", 9.8),
            ("CVE-2023-21980", "Vulnerabilidad en la función GROUP BY", 6.5)
        ],
        "8.0.32": [
            ("CVE-2023-21971", "Vulnerabilidad de divulgación de información", 7.5),
            ("CVE-2023-21954", "Vulnerabilidad en el procesamiento de consultas", 8.0)
        ],
        "8.0.33": [
            ("CVE-2023-22084", "Vulnerabilidad de carga de archivos arbitrarios", 8.8),
            ("CVE-2023-22078", "Vulnerabilidad de SQL injection", 7.2)
        ]
    },
    "Microsoft IIS": {
        "7.5": [
            ("CVE-2017-7269", "Vulnerabilidad de ejecución remota de código", 9.3)
        ],
        "10.0": [
            ("CVE-2020-0646", "Vulnerabilidad de elevación de privilegios", 7.8),
            ("CVE-2022-21907", "Vulnerabilidad de ejecución remota de código en HTTP.sys", 9.8)
        ]
    },
    "Redis": {
        "4.0.14": [
            ("CVE-2018-12453", "Vulnerabilidad de divulgación de información", 5.3)
        ],
        "5.0": [
            ("CVE-2019-10192", "Vulnerabilidad de denegación de servicio", 6.0),
            ("CVE-2022-24735", "Vulnerabilidad de seguridad en restricciones Lua", 7.5)
        ],
        "6.0": [
            ("CVE-2022-24735", "Vulnerabilidad de seguridad en restricciones Lua", 7.5),
            ("CVE-2022-35977", "Divulgación de información sensible", 5.5)
        ],
        "7.0": [
            ("CVE-2023-28856", "Vulnerabilidad de DoS en el procesamiento Lua", 7.5),
            ("CVE-2023-41053", "Autenticación inconsistente", 6.5)
        ]
    },
    "Postfix": {
        "3.3.0": [
            ("CVE-2019-10511", "Vulnerabilidad de DoS por consumo de recursos", 5.0)
        ],
        "3.5.9": [
            ("CVE-2021-33515", "Vulnerabilidad de spoofing de remitente", 5.9)
        ],
        "3.6.0": [
            ("CVE-2022-1012", "Vulnerabilidad en el manejo de mensajes", 6.5)
        ],
        "3.7.0": [
            ("CVE-2023-51764", "Vulnerabilidad en el procesamiento SMTP", 7.2)
        ]
    },
    "Sendmail": {
        "8.15.2": [
            ("CVE-2018-1301", "Vulnerabilidad de autenticación", 7.5)
        ],
        "8.16.0": [
            ("CVE-2020-7296", "Vulnerabilidad de ejecución remota de código", 8.8)
        ]
    },
    "Exim": {
        "4.92": [
            ("CVE-2019-15846", "Vulnerabilidad de ejecución remota de código", 9.8)
        ],
        "4.93": [
            ("CVE-2020-12783", "Vulnerabilidad de buffer overflow", 7.5)
        ],
        "4.94": [
            ("CVE-2021-27216", "Uso después de liberar memoria", 7.8),
            ("CVE-2020-28017", "Vulnerabilidad de escalada de privilegios", 7.8)
        ]
    },
    "MongoDB": {
        "4.0": [
            ("CVE-2019-2386", "Vulnerabilidad en restricciones de acceso", 8.1)
        ],
        "4.2": [
            ("CVE-2020-7921", "Vulnerabilidad de autenticación SCRAM", 8.1)
        ],
        "4.4": [
            ("CVE-2021-20312", "Divulgación de información sensible", 5.5)
        ],
        "5.0": [
            ("CVE-2022-24736", "Vulnerabilidad en el manejo de certificados", 7.5)
        ]
    },
    "PostgreSQL": {
        "10.6": [
            ("CVE-2019-10208", "Vulnerabilidad de revelación de información", 6.5)
        ],
        "11.5": [
            ("CVE-2019-10209", "Vulnerabilidad de buffer overflow", 7.1)
        ],
        "12.0": [
            ("CVE-2020-1720", "Vulnerabilidad de inyección SQL", 8.8)
        ],
        "13.0": [
            ("CVE-2021-3393", "Vulnerabilidad en pgcrypto", 5.9)
        ],
        "14.0": [
            ("CVE-2022-1552", "Vulnerabilidad de inyección en búsqueda de texto", 8.8)
        ],
        "15.0": [
            ("CVE-2023-2454", "Vulnerabilidad en la función GRANT", 7.8)
        ]
    },
    "PHP": {
        "7.2": [
            ("CVE-2019-11043", "Vulnerabilidad de ejecución remota de código", 9.8)
        ],
        "7.3": [
            ("CVE-2020-7070", "Vulnerabilidad de bypass de filtro", 8.2)
        ],
        "7.4": [
            ("CVE-2021-21702", "Vulnerabilidad de divulgación de información", 7.5),
            ("CVE-2022-31626", "Vulnerabilidad de desbordamiento de entero", 7.8)
        ],
        "8.0": [
            ("CVE-2022-31625", "Vulnerabilidad en la función unserialize()", 7.8),
            ("CVE-2023-0662", "Vulnerabilidad en la función openssl_verify", 7.5)
        ],
        "8.1": [
            ("CVE-2023-0662", "Vulnerabilidad en la función openssl_verify", 7.5),
            ("CVE-2023-3823", "Vulnerabilidad en la función random_int()", 5.9)
        ],
        "8.2": [
            ("CVE-2024-0480", "Buffer overflow en PDO", 7.5)
        ]
    },
    "Tomcat": {
        "8.5": [
            ("CVE-2020-1935", "Vulnerabilidad de revelación de información", 6.5),
            ("CVE-2021-25329", "Vulnerabilidad de divulgación de información", 5.3)
        ],
        "9.0": [
            ("CVE-2019-12418", "Vulnerabilidad de seguridad", 7.5),
            ("CVE-2020-13943", "Vulnerabilidad de DoS", 7.5),
            ("CVE-2023-41080", "Vulnerabilidad de denegación de servicio", 7.5)
        ],
        "10.0": [
            ("CVE-2022-45143", "Vulnerabilidad de filtrado de solicitudes", 5.9),
            ("CVE-2023-28708", "Vulnerabilidad de HTTP Request Smuggling", 7.5)
        ],
        "10.1": [
            ("CVE-2023-28708", "Vulnerabilidad de HTTP Request Smuggling", 7.5),
            ("CVE-2023-41080", "Vulnerabilidad de denegación de servicio", 7.5),
            ("CVE-2023-45648", "Bypass de restricciones de seguridad", 6.5)
        ]
    },
    "Nodejs": {
        "14.x": [
            ("CVE-2021-44531", "Vulnerabilidad de denegación de servicio", 7.5),
            ("CVE-2022-32212", "Vulnerabilidad en la gestión de DNS", 7.5)
        ],
        "16.x": [
            ("CVE-2022-32213", "Vulnerabilidad de DoS por consumo de CPU", 7.5),
            ("CVE-2023-30585", "Vulnerabilidad en el módulo Buffer", 5.9)
        ],
        "18.x": [
            ("CVE-2023-30589", "Vulnerabilidad en el módulo http", 7.5),
            ("CVE-2023-46809", "Vulnerabilidad de denegación de servicio", 7.5)
        ],
        "20.x": [
            ("CVE-2023-46809", "Vulnerabilidad de denegación de servicio", 7.5),
            ("CVE-2024-21890", "Vulnerabilidad en el manejo de URL", 8.1)
        ]
    },
    "Drupal": {
        "9.0": [
            ("CVE-2020-13663", "Vulnerabilidad XSS", 6.5)
        ],
        "9.3": [
            ("CVE-2022-25271", "Vulnerabilidad de acceso no autorizado", 8.1),
            ("CVE-2022-26492", "Vulnerabilidad de acceso a archivos", 7.5)
        ],
        "10.0": [
            ("CVE-2023-28771", "Vulnerabilidad de acceso a archivos", 8.2),
            ("CVE-2023-39879", "Cross-Site Scripting (XSS)", 6.1)
        ]
    },
    "WordPress": {
        "5.8": [
            ("CVE-2022-21661", "Vulnerabilidad de inyección SQL", 8.0),
            ("CVE-2022-21664", "Vulnerabilidad XSS", 6.1)
        ],
        "5.9": [
            ("CVE-2022-21662", "Vulnerabilidad de divulgación de información", 4.3)
        ],
        "6.0": [
            ("CVE-2022-3590", "Vulnerabilidad XSS", 6.1)
        ],
        "6.1": [
            ("CVE-2023-2745", "Vulnerabilidad de redirección", 6.1)
        ],
        "6.2": [
            ("CVE-2023-44164", "Vulnerabilidad de escalada de privilegios", 8.8),
            ("CVE-2023-2733", "Vulnerabilidad de registro falso", 7.5)
        ],
        "6.3": [
            ("CVE-2023-4634", "Vulnerabilidad de bypass de autenticación", 7.2)
        ],
        "6.4": [
            ("CVE-2023-45803", "Vulnerabilidad en la función wp_kses", 6.1),
            ("CVE-2023-45816", "Vulnerabilidad de divulgación de información", 5.3)
        ]
    },
    "Jenkins": {
        "2.346": [
            ("CVE-2022-34169", "Vulnerabilidad CSRF", 6.5)
        ],
        "2.361": [
            ("CVE-2023-24998", "Vulnerabilidad de divulgación de información", 5.5)
        ],
        "2.387": [
            ("CVE-2023-34456", "Vulnerabilidad XSS", 6.1)
        ],
        "2.401.1": [
            ("CVE-2023-37944", "Vulnerabilidad de acceso a archivos", 7.5)
        ]
    },
    "Jira": {
        "8.13": [
            ("CVE-2021-26086", "Vulnerabilidad de divulgación de información", 5.3),
            ("CVE-2021-26085", "Vulnerabilidad XSS", 6.1)
        ],
        "8.20": [
            ("CVE-2022-0540", "Vulnerabilidad de SSRF", 9.8),
            ("CVE-2022-26135", "Vulnerabilidad de divulgación de información", 5.3)
        ],
        "9.0": [
            ("CVE-2022-26135", "Vulnerabilidad de divulgación de información", 5.3)
        ],
        "9.4": [
            ("CVE-2023-22501", "Vulnerabilidad de autenticación", 9.8)
        ]
    },
    "Elasticsearch": {
        "7.10": [
            ("CVE-2021-22144", "Vulnerabilidad de escalada de privilegios", 7.8)
        ],
        "7.16": [
            ("CVE-2021-44228", "Vulnerabilidad Log4j (Log4Shell)", 10.0)
        ],
        "7.17": [
            ("CVE-2022-23708", "Vulnerabilidad de divulgación de información", 5.5)
        ],
        "8.0": [
            ("CVE-2022-23708", "Vulnerabilidad de divulgación de información", 5.5)
        ],
        "8.5": [
            ("CVE-2022-4246", "Vulnerabilidad de divulgación de información", 5.5)
        ],
        "8.7": [
            ("CVE-2023-31419", "Vulnerabilidad de divulgación de información", 7.5)
        ]
    }
}