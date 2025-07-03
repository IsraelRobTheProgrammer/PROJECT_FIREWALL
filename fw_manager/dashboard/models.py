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
    description = models.TextField()

    class Meta:
        verbose_name = "Threat Log"
        verbose_name_plural = "Threat Logs"

    def __str__(self):
        return f"{self.threat_type} from {self.source_ip} to {self.destination_ip} at {self.timestamp}"


class BlockedIP(models.Model):
    """
    Model to store blocked IP addresses.
    """
    
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

    protocol = models.CharField(max_length=10, choices=[("tcp", "TCP"), ("udp", "UDP")])
    port = models.IntegerField()
    action = models.CharField(
        max_length=10, choices=[("ACCEPT", "ACCEPT"), ("DROP", "DROP")]
    )
    direction = models.CharField(
        max_length=10, choices=[("INPUT", "INPUT"), ("OUTPUT", "OUTPUT")]
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = "Firewall Rule"
        verbose_name_plural = "Firewall Rules"
        unique_together = ("protocol", "port", "action", "direction")

    def __str__(self):
        return f"{self.direction} {self.protocol}:{self.port} {self.action}"
