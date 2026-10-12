"""One-shot generator for wordlists/default.txt.

Builds a de-duplicated, lowercase list of real subdomain labels from curated
category seeds plus a bounded set of systematic numbered variants (e.g.
ns1..ns10, web01..web20). Every emitted label is validated against the same
RFC-1035 label rule the app enforces. Run:

    python wordlists/gen_wordlist.py

This script is a build helper; the app only reads the generated default.txt.
"""

import re

LABEL_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")

# Curated base labels, grouped only for readability (order is not preserved
# beyond the final sort+dedup).
BASE = [
    # web / app front-ends
    "www", "www1", "www2", "www3", "web", "web1", "web2", "webapp", "app",
    "apps", "application", "portal", "portals", "home", "site", "sites",
    "public", "mobile", "m", "wap", "touch", "amp", "static", "assets",
    "asset", "img", "images", "image", "media", "video", "videos", "audio",
    "cdn", "cdn1", "cdn2", "edge", "origin", "cache", "files", "file",
    "download", "downloads", "upload", "uploads", "content", "cms",
    # mail
    "mail", "mail1", "mail2", "email", "webmail", "smtp", "smtp1", "smtp2",
    "imap", "pop", "pop3", "mx", "mx1", "mx2", "mx3", "mta", "relay",
    "autodiscover", "autoconfig", "exchange", "owa", "outlook", "zimbra",
    "mailgun", "mailchimp", "newsletter", "mailer", "bounce", "spam",
    "antispam", "mx0", "mail3", "smtp3",
    # name servers / dns
    "ns", "ns1", "ns2", "ns3", "ns4", "ns5", "dns", "dns1", "dns2", "resolver",
    "nameserver", "domain", "whois", "registry", "soa",
    # environments
    "dev", "dev1", "dev2", "develop", "development", "devel", "staging",
    "stage", "stg", "prod", "production", "test", "test1", "test2", "testing",
    "qa", "qa1", "qa2", "uat", "uat1", "sandbox", "sbox", "demo", "demo1",
    "demo2", "beta", "beta1", "alpha", "preprod", "pre", "preview", "canary",
    "nightly", "experimental", "lab", "labs", "poc", "pilot", "trial",
    "release", "integration", "int", "perf", "load", "stress",
    # api / services
    "api", "api1", "api2", "api3", "apis", "rest", "graphql", "grpc", "ws",
    "websocket", "soap", "rpc", "service", "services", "svc", "micro",
    "gateway", "gw", "proxy", "proxies", "reverse", "lb", "lb1", "lb2",
    "balancer", "ingress", "egress", "router", "route", "endpoint",
    "backend", "frontend", "middleware", "connector", "bridge", "hub",
    # admin / management
    "admin", "admin1", "admin2", "administrator", "adm", "manage", "manager",
    "management", "mgmt", "console", "control", "controlpanel", "panel",
    "cpanel", "whm", "plesk", "webadmin", "siteadmin", "sysadmin", "root",
    "superuser", "operator", "ops", "noc", "soc", "helpdesk", "dashboard",
    "dash", "board", "portal-admin", "backoffice", "office", "intranet",
    "internal", "internal1", "corp", "corporate", "private", "secure",
    "secured", "protected", "restricted",
    # auth / identity
    "auth", "auth1", "auth2", "oauth", "oauth2", "sso", "saml", "openid",
    "oidc", "idp", "login", "logon", "signin", "signup", "register",
    "account", "accounts", "acct", "user", "users", "profile", "profiles",
    "identity", "id", "ldap", "ad", "activedirectory", "kerberos", "radius",
    "mfa", "2fa", "token", "keycloak", "okta", "onelogin", "jumpcloud",
    "passport", "credential", "credentials", "session",
    # vpn / remote
    "vpn", "vpn1", "vpn2", "remote", "remote1", "access", "gateway-vpn",
    "ssl", "sslvpn", "anyconnect", "pulse", "citrix", "rdp", "rds", "ts",
    "terminal", "ssh", "sftp", "ftp", "ftp1", "ftp2", "ftps", "tftp",
    "telnet", "bastion", "jump", "jumphost", "jumpbox", "pivot", "tunnel",
    "wireguard", "openvpn", "ipsec", "l2tp", "pptp",
    # source control / ci-cd / dev tooling
    "git", "git1", "gitlab", "github", "gitea", "gogs", "bitbucket", "svn",
    "mercurial", "hg", "cvs", "repo", "repos", "repository", "code",
    "source", "jenkins", "ci", "cd", "cicd", "build", "builds", "builder",
    "drone", "travis", "circleci", "bamboo", "teamcity", "gocd", "argocd",
    "spinnaker", "tekton", "actions", "runner", "runners", "agent", "agents",
    "artifactory", "nexus", "registry", "registry1", "docker", "harbor",
    "quay", "packages", "package", "npm", "pypi", "maven", "gradle",
    # project / collaboration tooling
    "jira", "confluence", "wiki", "wikis", "redmine", "trac", "mantis",
    "bugzilla", "youtrack", "trello", "asana", "basecamp", "notion",
    "slack", "mattermost", "rocketchat", "discord", "teams", "zoom",
    "webex", "meet", "chat", "chatops", "im", "messaging", "comms",
    "sharepoint", "nextcloud", "owncloud", "seafile", "drive", "docs",
    "doc", "documents", "office365", "o365",
    # monitoring / observability
    "grafana", "prometheus", "alertmanager", "kibana", "elastic",
    "elasticsearch", "logstash", "kba", "splunk", "graylog", "loki",
    "jaeger", "zipkin", "tempo", "thanos", "cortex", "victoriametrics",
    "datadog", "newrelic", "sentry", "rollbar", "bugsnag", "statuspage",
    "status", "statuscheck", "health", "healthcheck", "metrics", "monitor",
    "monitoring", "mon", "nagios", "zabbix", "icinga", "cacti", "munin",
    "collectd", "telegraf", "influx", "influxdb", "uptime", "pingdom",
    "observability", "apm", "trace", "tracing", "logs", "log", "logging",
    "syslog", "audit", "siem",
    # databases / data stores
    "db", "db1", "db2", "database", "databases", "sql", "mysql", "mariadb",
    "postgres", "postgresql", "pg", "pgsql", "oracle", "mssql", "sqlserver",
    "redis", "memcached", "memcache", "mongo", "mongodb", "cassandra",
    "couchdb", "couchbase", "dynamodb", "neo4j", "arangodb", "rethinkdb",
    "clickhouse", "cockroach", "timescale", "etcd", "consul", "zookeeper",
    "vault", "secrets", "secret", "kv", "datastore", "warehouse", "dwh",
    "lake", "datalake", "analytics", "bi", "metabase", "superset", "looker",
    "tableau", "powerbi", "redash", "pentaho", "airflow", "dagster",
    "kafka", "rabbitmq", "activemq", "nats", "pulsar", "mq", "queue",
    "broker", "stream", "streaming", "pubsub",
    # cloud / infra / orchestration
    "cloud", "aws", "azure", "gcp", "gce", "ec2", "s3", "s3-website", "ecs",
    "eks", "aks", "gke", "k8s", "kubernetes", "kube", "openshift", "ocp",
    "rancher", "nomad", "mesos", "swarm", "compose", "helm", "terraform",
    "ansible", "puppet", "chef", "salt", "saltstack", "cloudinit",
    "infra", "infrastructure", "platform", "paas", "iaas", "saas",
    "orchestrator", "scheduler", "node", "node1", "node2", "worker",
    "worker1", "worker2", "master", "master1", "control-plane", "cp",
    "compute", "storage", "block", "object", "nfs", "ceph", "gluster",
    "minio", "backup", "backups", "bak", "snapshot", "snapshots", "restore",
    "archive", "archives", "dr", "failover", "replica", "replica1",
    "standby", "secondary", "primary",
    # ecommerce / payments / business apps
    "shop", "shops", "store", "stores", "cart", "checkout", "payment",
    "payments", "pay", "billing", "invoice", "invoices", "order", "orders",
    "catalog", "product", "products", "inventory", "warehouse1", "pos",
    "merchant", "stripe", "paypal", "braintree", "square", "adyen",
    "subscription", "subscriptions", "pricing", "quote", "quotes", "crm",
    "erp", "salesforce", "hubspot", "zoho", "sap", "netsuite", "dynamics",
    "finance", "accounting", "payroll", "hr", "hrms", "ats", "recruiting",
    "ecommerce", "commerce", "marketplace",
    # content / marketing / public
    "blog", "blogs", "news", "press", "forum", "forums", "community",
    "discuss", "board1", "help", "helpcenter", "support", "support1",
    "ticket", "tickets", "kb", "knowledge", "faq", "guide", "guides",
    "manual", "manuals", "learn", "learning", "lms", "academy", "training",
    "course", "courses", "edu", "events", "event", "webinar", "landing",
    "lp", "promo", "campaign", "campaigns", "marketing", "mktg", "ads",
    "advert", "advertising", "track", "tracker", "tracking", "analytics1",
    "pixel", "tag", "tagmanager", "gtm", "seo", "survey", "feedback",
    "review", "reviews", "rating", "search", "find", "finder", "directory",
    "map", "maps", "geo", "location", "locator",
    # misc common
    "old", "new", "legacy", "temp", "tmp", "backup1", "test3", "demo3",
    "example", "sample", "default", "main", "core", "central", "global",
    "local", "localhost", "host", "hosting", "server", "server1", "server2",
    "srv", "srv1", "box", "vm", "vm1", "container", "pod", "app1", "app2",
    "app3", "svc1", "svc2", "api4", "web3", "portal1", "portal2",
    "client", "clients", "customer", "customers", "partner", "partners",
    "vendor", "vendors", "supplier", "affiliate", "reseller", "b2b", "b2c",
    "enterprise", "ent", "team", "teams1", "group", "groups", "org",
    "department", "dept", "division", "unit", "branch", "region", "regional",
    "us", "eu", "uk", "de", "fr", "jp", "cn", "in", "au", "ca", "br", "ru",
    "asia", "emea", "apac", "latam", "na", "east", "west", "north", "south",
    "us-east", "us-west", "eu-west", "eu-central", "ap-south",
    "cluster", "cluster1", "cluster2", "zone", "zone1", "zone2", "dc", "dc1",
    "dc2", "datacenter", "rack", "pool", "farm", "grid",
    "gateway1", "fw", "firewall", "waf", "ids", "ips", "scanner", "scan",
    "pentest", "security", "sec", "cert", "ca", "pki", "ocsp", "crl",
    "time", "ntp", "clock", "sync", "scheduler1", "cron", "job", "jobs",
    "task", "tasks", "worker3", "queue1", "batch", "etl", "pipeline",
    "feature", "features", "flag", "flags", "config", "configuration",
    "settings", "setup", "install", "installer", "update", "updates",
    "upgrade", "patch", "release1", "deploy", "deployment", "rollout",
    "www4", "www5", "api5", "api6", "v1", "v2", "v3", "v4", "api-v1",
    "api-v2", "staging-api", "dev-api", "prod-api", "test-api", "qa-api",
    "beta-api", "internal-api", "public-api", "partner-api", "admin-api",
    "mobile-api", "gateway-api",
]

# Systematic numbered expansions (bounded) for very common host prefixes.
NUMBERED_PREFIXES = {
    "ns": 10, "mx": 10, "mail": 10, "smtp": 6, "web": 20, "www": 10,
    "app": 20, "api": 10, "db": 10, "node": 30, "worker": 20, "server": 30,
    "srv": 20, "vpn": 10, "lb": 8, "cache": 8, "cdn": 8, "proxy": 8,
    "host": 30, "vm": 30, "pod": 20, "edge": 8, "gw": 8, "dns": 6,
    "redis": 6, "mongo": 6, "postgres": 6, "mysql": 6, "kafka": 6,
    "es": 6, "elastic": 6, "k8s": 8, "monitor": 6, "log": 6, "stage": 6,
    "test": 10, "dev": 10, "qa": 6, "uat": 6, "demo": 6, "staging": 6,
    "prod": 6, "backup": 8, "store": 6, "shop": 6, "portal": 6, "admin": 6,
    "auth": 6, "gateway": 6, "cluster": 6, "zone": 6, "dc": 6, "pool": 6,
    "runner": 10, "agent": 10, "build": 8, "ci": 6, "jenkins": 4, "git": 4,
    "registry": 4, "docker": 4, "grafana": 4, "kibana": 4, "prometheus": 4,
    "vault": 4, "consul": 4, "etcd": 4,
}


def build() -> list[str]:
    labels: list[str] = []
    seen: set[str] = set()

    def add(label: str) -> None:
        label = label.strip().lower()
        if not label or label in seen:
            return
        if not LABEL_RE.match(label):
            return
        seen.add(label)
        labels.append(label)

    for item in BASE:
        add(item)

    for prefix, count in NUMBERED_PREFIXES.items():
        for i in range(1, count + 1):
            add(f"{prefix}{i}")
            add(f"{prefix}{i:02d}")
            add(f"{prefix}-{i}")

    labels.sort()
    return labels


if __name__ == "__main__":
    out = build()
    with open("wordlists/default.txt", "w", encoding="utf-8") as fh:
        fh.write("\n".join(out) + "\n")
    print(f"wrote {len(out)} labels")
