# coding=utf-8
"""Cuckoo AUCR plugin default database tables."""
from aucr_app import db


class CuckooReports(db.Model):
    """Cuckoo Report database table."""

    __tablename__ = 'cuckoo_reports'
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(3072))
    report_ids = db.Column(db.String(3072))
    md5_hash = db.Column(db.String(32))
    modify_time = db.Column(db.DateTime)

    def __repr__(self):
        return '<Cuckoo Reports {}>'.format(self.id)
