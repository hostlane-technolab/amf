from django.core.management.base import BaseCommand
from django.utils import timezone
from django.db import transaction
from adminapp.models import Tenant, Bill, BillingConfiguration
import logging

logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = "Generate bills automatically for tenants based on their configuration"

    def add_arguments(self, parser):
        parser.add_argument("--tenant-id", type=int, help="Generate bills for a specific tenant ID only")
        parser.add_argument("--dry-run", action="store_true", help="Show what bills would be generated without actually creating them")
        parser.add_argument("--force", action="store_true", help="Force generation even if bills already exist for the current period")

    def handle(self, *args, **options):
        tenant_id = options.get("tenant_id")
        dry_run = options.get("dry_run", False)
        force = options.get("force", False)

        self.stdout.write(self.style.NOTICE("Starting automatic bill generation..."))

        # Get tenants
        if tenant_id:
            tenants = Tenant.objects.filter(id=tenant_id, is_active=True)
            if not tenants.exists():
                self.stdout.write(self.style.ERROR(f"Tenant with ID {tenant_id} not found or inactive"))
                return
        else:
            tenants = Tenant.objects.filter(is_active=True)

        bills_generated = []
        current_date = timezone.now().date()

        for tenant in tenants:
            try:
                # Skip tenants without billing config
                if not hasattr(tenant, "billing_configuration"):
                    self.stdout.write(self.style.WARNING(f"Skipping {tenant.company_name}: No billing configuration"))
                    continue

                config = tenant.billing_configuration

                # Skip if not time to generate
                if not self._should_generate_bill(tenant, config, current_date, force):
                    continue

                # Skip if bill already exists (unless forced)
                if not force and self._bill_exists_for_period(tenant, current_date, config):
                    self.stdout.write(self.style.WARNING(f"Bill already exists for {tenant.company_name} for this period"))
                    continue

                if dry_run:
                    msg = f"[DRY RUN] Would generate bill for: {tenant.company_name}"
                    self.stdout.write(self.style.NOTICE(msg))
                    bills_generated.append(msg)
                else:
                    bill = self._create_bill(tenant, config, current_date)
                    bills_generated.append(bill)
                    self.stdout.write(self.style.SUCCESS(f"Generated bill {bill.bill_number} for {tenant.company_name}"))

            except Exception as e:
                self.stdout.write(self.style.ERROR(f"Error generating bill for {tenant.company_name}: {e}"))
                logger.error(f"Bill generation error for tenant {tenant.id}: {e}")

        # Summary
        if bills_generated:
            if dry_run:
                self.stdout.write(self.style.SUCCESS(f"Dry run complete. Would generate {len(bills_generated)} bills"))
            else:
                self.stdout.write(self.style.SUCCESS(f"Successfully generated {len(bills_generated)} bills"))
                for bill in bills_generated:
                    if hasattr(bill, "bill_number"):
                        self.stdout.write(f"- {bill.bill_number} for {bill.tenant.company_name}")
        else:
            self.stdout.write(self.style.WARNING("No bills generated"))

    # -------------------------------
    # Helpers
    # -------------------------------

    def _should_generate_bill(self, tenant, config, current_date, force):
        """Check billing cycle rules"""
        if force:
            return True

        cycle = getattr(config, "billing_cycle", None)
        if not cycle:
            return True

        cycle = cycle.lower()
        if cycle == "monthly":
            billing_day = getattr(config, "billing_day", 1)
            return current_date.day == billing_day
        elif cycle == "quarterly":
            return current_date.month in [1, 4, 7, 10] and current_date.day == 1
        elif cycle == "yearly":
            return current_date.month == 1 and current_date.day == 1

        return True

    def _bill_exists_for_period(self, tenant, current_date, config):
        """Check if bill already exists for this month"""
        return Bill.objects.filter(
            tenant=tenant,
            bill_date__year=current_date.year,
            bill_date__month=current_date.month,
        ).exists()

    @transaction.atomic
    def _create_bill(self, tenant, config, current_date):
        """Create a bill"""
        bill_number = self._generate_bill_number(tenant, current_date)

        base_amount = getattr(config, "base_amount", 0)
        tax_rate = getattr(config, "tax_rate", 0)
        tax_amount = base_amount * (tax_rate / 100)
        total_amount = base_amount + tax_amount

        bill = Bill.objects.create(
            tenant=tenant,
            bill_number=bill_number,
            bill_date=current_date,
            due_date=self._calculate_due_date(current_date, config),
            base_amount=base_amount,
            tax_amount=tax_amount,
            total_amount=total_amount,
            status="pending",
        )
        return bill

    def _generate_bill_number(self, tenant, current_date):
        """Generate sequential bill number per tenant per period"""
        prefix = f"BILL-{tenant.id:04d}"
        suffix = current_date.strftime("%Y%m")
        existing_count = Bill.objects.filter(bill_number__startswith=f"{prefix}-{suffix}").count()
        return f"{prefix}-{suffix}-{existing_count+1:03d}"

    def _calculate_due_date(self, bill_date, config):
        """Due date based on payment terms"""
        from datetime import timedelta
        terms = getattr(config, "payment_terms_days", 30)
        return bill_date + timedelta(days=terms)
