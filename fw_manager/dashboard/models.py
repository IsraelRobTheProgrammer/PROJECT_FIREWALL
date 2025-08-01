from django.db import models

# Create your models here.


class ThreatLog(models.Model):
    """
    Model to store threat logs.
    """

    timestamp = models.DateTimeField(auto_now_add=True)
    source_ip = models.GenericIPAddressField()
    destination_ip = models.GenericIPAddressField()
    threat_type = models.CharField(max_length=100)
    protcol = models.CharField(
        max_length=10, choices=[("tcp", "TCP"), ("udp", "UDP")], default="tcp"
    )

    class Meta:
        verbose_name = "Threat Log"
        verbose_name_plural = "Threat Logs"

    def __str__(self):
        return f"{self.threat_type} from {self.source_ip} to {self.destination_ip} at {self.timestamp}"


class BlockedIP(models.Model):
    """
    Model to store blocked IP addresses.
    """

    source = models.CharField(max_length=50, blank=True, null=True)
    ip_address = models.GenericIPAddressField(unique=True)
    reason = models.CharField(max_length=255, blank=True, null=True)
    blocked_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = "Blocked IP"
        verbose_name_plural = "Blocked IPs"

    def __str__(self):
        return f"Blocked IP: {self.ip_address} - Reason: {self.reason}"


class FirewallRule(models.Model):
    """
    Model to store firewall rules.
    """

    name = models.CharField(max_length=100, unique=True, default="Unnamed Rule")
    protocol = models.CharField(max_length=10, choices=[("tcp", "TCP"), ("udp", "UDP")])
    source_ip = models.GenericIPAddressField(blank=True, null=True)
    dest_ip = models.GenericIPAddressField(blank=True, null=True)
    # mac_address = models.CharField(max_length=17, blank=True, null=True)  # MAC address in format XX:XX:XX:XX:XX:XX
    source_port = models.IntegerField(blank=True, null=True)  # Optional source port
    dest_port = models.IntegerField(blank=True, null=True)  # Optional destination port
    port = models.IntegerField()
    action = models.CharField(
        max_length=10, choices=[("ACCEPT", "ACCEPT"), ("DROP", "DROP")]
    )
    direction = models.CharField(
        max_length=10, choices=[("INPUT", "INPUT"), ("OUTPUT", "OUTPUT")]
    )
    description = models.TextField(
        max_length=255, blank=True, null=True, default="No description added"
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = "Firewall Rule"
        verbose_name_plural = "Firewall Rules"
        constraints = [
            models.UniqueConstraint(
                fields=["protocol", "port", "action", "direction"],
                name="unique_firewall_rule",
            )
        ]

    def __str__(self):
        return f"{self.direction} {self.protocol}:{self.port} {self.action}"
