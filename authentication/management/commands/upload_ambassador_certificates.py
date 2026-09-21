import os
import re

from django.core.files import File
from django.core.management.base import BaseCommand, CommandError

from authentication.models import AmbassadorCertificate, CustomUser


def normalize_name(value):
    # Lowercase, collapse all whitespace - matches "Eniola  Omotayo Ajadi"
    # to a filename saved as "Eniola Omotayo Ajadi.pdf" just as readily as
    # a DB record with the last name concatenated with no space at all
    # ("OmotayoAjadi"), which does happen (see 2072's record).
    return re.sub(r"\s+", "", value or "").strip().lower()


class Command(BaseCommand):
    help = (
        "Bulk-create AmbassadorCertificate rows from a folder of files named "
        "'First Last.pdf' / 'First Last.png', matched to CustomUser by "
        "normalized full name. Use --apply to actually save; without it, "
        "this only previews matches."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--dir", required=True, help="Folder containing the certificate files."
        )
        parser.add_argument("--apply", action="store_true")

    def handle(self, *args, **options):
        directory = options["dir"]
        if not os.path.isdir(directory):
            raise CommandError(f"Not a directory: {directory}")

        files = [
            f
            for f in os.listdir(directory)
            if f.lower().endswith((".pdf", ".png", ".jpg", ".jpeg"))
        ]
        if not files:
            self.stdout.write("No certificate files found in that folder.")
            return

        # Ambiguity guard: two ambassadors sharing a normalized name would
        # silently attach a certificate to the wrong account - build the
        # lookup once and fail loudly on any collision instead of guessing.
        users_by_name = {}
        collisions = set()
        for u in CustomUser.objects.exclude(first_name="").exclude(last_name=""):
            key = normalize_name(f"{u.first_name} {u.last_name}")
            if not key:
                continue
            if key in users_by_name:
                collisions.add(key)
            else:
                users_by_name[key] = u

        matched, unmatched, ambiguous = [], [], []
        for filename in files:
            stem = os.path.splitext(filename)[0]
            key = normalize_name(stem)
            if key in collisions:
                ambiguous.append(filename)
            elif key in users_by_name:
                matched.append((filename, users_by_name[key]))
            else:
                unmatched.append(filename)

        for filename, user in matched:
            existing = getattr(user, "ambassador_certificate", None)
            note = " (already has one - will be replaced)" if existing else ""
            self.stdout.write(f"MATCH  {filename} -> {user.email}{note}")
        for filename in ambiguous:
            self.stdout.write(f"SKIP   {filename} -> multiple users share this name")
        for filename in unmatched:
            self.stdout.write(f"NO MATCH  {filename}")

        self.stdout.write(
            f"\n{len(matched)} matched, {len(ambiguous)} ambiguous, {len(unmatched)} unmatched."
        )

        if not options["apply"]:
            self.stdout.write("DRY RUN: no changes made. Re-run with --apply to save.")
            return

        for filename, user in matched:
            path = os.path.join(directory, filename)
            with open(path, "rb") as fh:
                django_file = File(fh, name=filename)
                cert, _ = AmbassadorCertificate.objects.update_or_create(
                    user=user,
                    defaults={"dismissed_at": None},
                )
                cert.file.save(filename, django_file, save=True)
            self.stdout.write(f"Saved certificate for {user.email}")

        self.stdout.write(self.style.SUCCESS(f"Done - {len(matched)} certificates saved."))
