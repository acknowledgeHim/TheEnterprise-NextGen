import sys
from datetime import datetime
from sqlalchemy import create_engine
from sqlalchemy import Table, Column, Integer, String, Date, DateTime, ForeignKey, Boolean, Text
from sqlalchemy.orm import relationship, backref
from sqlalchemy.ext.declarative import declarative_base
from common import common

Base = declarative_base()

def initialize(sqlite_file):
    """ Create SQLite Database. """
    try:
        engine = create_engine('sqlite:///' + sqlite_file, connect_args={"check_same_thread": False})
        Base.metadata.create_all(engine)
        return True
    except Exception as e:
        print("common.sqlalchemy_model 17 except: " + str(e) + " Error on line {}".format(sys.exc_info()[-1].tb_lineno))
        return False


def retrieve_required_fields(db_table_name):
    """Sets up required fields that can not be blank for each table and returns fields that can not be blank."""
    if db_table_name == "EmailEvent":
        return ["hashval", "event", "subject", "start_or_end"]
    elif db_table_name == "FlaskUser":
        return ["hashval", "username", "passwd"]
    elif db_table_name == "Information":
        return ["hashval", "version"]
    elif db_table_name == "ClientContact":
        return ["hashval", "contact_name", "contact_email", "real_time_notification"]
    elif db_table_name == "CorpContact":
        return ["hashval", "email", "client_relation", "real_time_notification"]
    elif db_table_name == "CurrentLocation":
        return ["hashval", "current_location", "modified_by"]
    elif db_table_name == "DevicePort":
        return ["hashval", "ip", "port", "protocol", "source", "engagementdevice_id", "validated", "stealth"]
    elif db_table_name == "Engagement":
        return ["hashval", "client_number", "client_name", "engagement_number", "start_date", "external_only"]
    elif db_table_name == "EngagementDevice":
        return ["hashval", "target_name", "scope_id", "source"]
    elif db_table_name == "Location":
        return ["hashval", "name"]
    elif db_table_name == "Log":
        return ["hashval", "start_time", "target", "scope_id", "source"]
    elif db_table_name == "Person":
        return ["hashval", "source", "location_id"]
    elif db_table_name == "Recon":
        return ["hashval", "record", "recon_type", "scope_id"]
    elif db_table_name == "Scope":
        return ["hashval", "entry", "location_id"]
    elif db_table_name == "Phishing":
        return ["hashval", "location_id", "scenario_id", "sent_to", "received_response"]
    elif db_table_name == "PhishingScenario":
        return ["hashval", "scenario", "scenario_file", "email_server", "smtp_from", "data_from",
                "send_to_already_phished", "priority"]
    elif db_table_name == "Credential":
        return ["hashval", "username", "source", "salted_hash", "disabled", "pwdnotexpire", "da", "la",
                "validated_credential"]
    elif db_table_name == "Result":
        return ["hashval", "scope_id", "engagementdevice_id", "finding_title", "tool", "target", "port", "protocol"]
    elif db_table_name == "TesterDevice":
        return ["hashval", "location_id", "tester_ip"]
    elif db_table_name == "Webspider":
        return ["hashval", "url", "link"]
    elif db_table_name == "ForensicLog":
        return ["hashval", "scope_id", "event", "run_date", "log_name"]
    elif db_table_name == "EventMessage":
        return ["hashval", "message"]

def retrieve_hash_fields(db_table_name):
    """Sets up hashval for each table and returns fields used to create the hashval."""
    if db_table_name == "EmailEvent":
        return ['event', 'start_or_end']
    elif db_table_name == "FlaskUser":
        return ['username', 'passwd']
    elif db_table_name == "Information":
        return ["version"]
    elif db_table_name == "ClientContact":
        return ["contact_email"]
    elif db_table_name == "CorpContact":
        return ["email"]
    elif db_table_name == "CurrentLocation":
        return ["modified_by"]
    elif db_table_name == "DevicePort":
        return ["ip", "port", "protocol", "engagementdevice_id"]
    elif db_table_name == "Engagement":
        return ["start_date"]
    elif db_table_name == "EngagementDevice":
        return ["target_name", "scope_id"]
    elif db_table_name == "Location":
        return ["name"]
    elif db_table_name == "Log":
        return ["start_time", "scope_id", "target"]
    elif db_table_name == "Person":
        return ["email", "full_name", "organization", "location_id"]
    elif db_table_name == "Recon":
        return ["record", "recon_type"]
    elif db_table_name == "Result":
        return ["engagementdevice_id", "finding_title", "tool", "target", "port", "protocol"]
    elif db_table_name == "Scope":
        return ["entry", "location_id"]
    elif db_table_name == "Phishing":
        return ["location_id", "scenario_id", "sent_to"]
    elif db_table_name == "PhishingScenario":
        return ["scenario", "smtp_from", "data_from"]
    elif db_table_name == "Credential":
        return ["domain", "username", "salted_hash", "hash_value", "passwd", "status", "engagementdevice_id", "service"]
    elif db_table_name == "TesterDevice":
        return ["location_id", "tester_ip"]
    elif db_table_name == "Webspider":
        return ["url"]
    elif db_table_name == "ForensicLog":
        return ["scope_id", "event", "run_date", "log_name"]
    elif db_table_name == "EventMessage":
        return ['message']


class Information(Base):
    """
    hashval -- version
    """

    __tablename__ = 'information'

    id = Column(Integer, primary_key=True)
    hashval = Column(String(512), unique=True, nullable=False)
    version = Column(String(255), default='0.1', unique=True)
    modified_by = Column(String(128), default=common.get_tester(), nullable=False)

    def __repr__(self):
        return self.version


class CurrentLocation(Base):
    """
    hashval -- current_location + modified_by
    """
    __tablename__ = 'CurrentLocation'

    id = Column(Integer, primary_key=True)
    hashval = Column(String(512), unique=True, nullable=False)
    current_location = Column(String(30), nullable=False)
    modified_by = Column(String(128), default=common.get_tester(), nullable=False)
    modified_date = Column(DateTime, default=datetime.utcnow)

    def __repr__(self):
        return self.current_location + (self.modified_by)


class ClientContact(Base):
    """
    hashval -- email
    """
    __tablename__ = 'ClientContact'

    id = Column(Integer, primary_key=True)
    hashval = Column(String(512), unique=True, nullable=False)
    contact_name = Column(String(255), nullable=False)
    contact_email = Column(String(255), nullable=False, unique=True)
    title = Column(String(255), nullable=True)
    email_signature = Column(Text, nullable=True)
    real_time_notification = Column(Boolean, default=False)
    modified_by = Column(String(128), default=common.get_tester(), nullable=False)
    modified_date = Column(DateTime, default=datetime.utcnow)

    def __repr__(self):
        return self.contact_email


class CorpContact(Base):
    """
    hashval -- email
    """
    __tablename__ = 'CorpContact'

    id = Column(Integer, primary_key=True)
    hashval = Column(String(512), unique=True, nullable=False)
    email = Column(String(255), nullable=False, unique=True)
    client_relation = Column(String(128), default='tester')
    real_time_notification = Column(Boolean, default=False)
    modified_by = Column(String(128), default=common.get_tester(), nullable=False)
    modified_date = Column(DateTime, default=datetime.utcnow)

    def __repr__(self):
        return self.email

class Engagement(Base):
    """
    hashval -- client_number + engagement_number
    """

    __tablename__ = 'Engagement'

    id = Column(Integer, primary_key=True)
    hashval = Column(String(512), unique=True, nullable=False)
    client_number = Column(String(255), nullable=False)
    client_name = Column(String(255), nullable=False)
    engagement_number = Column(String(255), nullable=False)
    start_date = Column(Date, nullable=False)
    expected_completion_date = Column(Date, nullable=True)
    end_date = Column(Date, nullable=True)
    hours_activity_allowed = Column(String(255), nullable=True, default=0000-2400) #anytime default
    email_tester = Column(Boolean, default=True)
    email_company_contact = Column(Boolean, default=False)
    email_client_contact = Column(Boolean, default=False)
    rerun_tool = Column(Boolean, default=False)
    external_only = Column(Boolean, default=False)
    base_results_off_live_hosts_ping = Column(Boolean, default=False)
    auto_run = Column(String(255), default='recon')
    can_send_auto_notification = Column(Boolean, default=False)
    create_finding_for_internet_openport = Column(Boolean, default=True)
    identification = Column(Text, unique=False, nullable=True)
    modified_by = Column(String(128), default=common.get_tester(), nullable=False)
    modified_date = Column(DateTime, default=datetime.utcnow)

    def __repr__(self):
        return self.client_number + " " + self.client_name


class DevicePort(Base):
    """
    hashval -- ip + port + protocol + engagement_device_id
    """
    __tablename__ = 'DevicePort'

    id = Column(Integer, primary_key=True)
    hashval = Column(String(512), unique=True, nullable=False)
    engagementdevice_id = Column(Integer, ForeignKey('EngagementDevice.id', ondelete='cascade'), nullable=False)
    ip = Column(String(512), nullable=False)
    port = Column(String(50), nullable=False)
    protocol = Column(String(20), nullable=False)
    port_description = Column(Text, nullable=True)
    start_time = Column(DateTime, nullable=True)
    end_time = Column(DateTime, nullable=True)
    stealth = Column(Boolean, default=False)
    validated = Column(Boolean, default=True)
    source = Column(String(512), nullable=False, default='manual')
    modified_by = Column(String(128), default=common.get_tester(), nullable=False)
    modified_date = Column(DateTime, default=datetime.utcnow)

    def __repr__(self):
        return self.ip + ":" + self.port + " " + self.protocol


class Recon(Base):
    """
    hashval -- record + type + scope_id
    """
    __tablename__ = 'Recon'

    id = Column(Integer, primary_key=True)
    hashval = Column(String(512), unique=True, nullable=False)
    scope_id = Column(Integer, ForeignKey('Scope.id', ondelete='cascade'), nullable=False)
    recon_type = Column(String(512), nullable=False)
    record = Column(String(512), nullable=False)
    info = Column(String(512), nullable=True)
    associated_info = Column(String(512), nullable=True)
    recon_description = Column(String(512), nullable=True)
    organization = Column(String(512), nullable=True)
    source = Column(String(512), nullable=False, default='manual')
    modified_by = Column(String(128), default=common.get_tester(), nullable=False)
    modified_date = Column(DateTime, default=datetime.utcnow)

    def __repr__(self):
        return self.record + " (" + self.recon_type + ")"

class Person(Base):
    """
    hashval -- email + full_name + organization + location_id
    """
    __tablename__ = 'Person'

    id = Column(Integer, primary_key=True)
    hashval = Column(String(512), unique=True, nullable=False)
    location_id = Column(Integer, ForeignKey('Location.id', ondelete='cascade'), nullable=False)
    full_name = Column(String(512), nullable=True)
    email = Column(String(512), nullable=True)
    person_info = Column(Text, nullable=True)
    associated_info = Column(String(512), nullable=True)
    person_description = Column(Text, nullable=True)
    organization = Column(String(512), nullable=True)
    title = Column(String(128), nullable=True)
    phone = Column(String(128), nullable=True)
    full_address = Column(Text, nullable=True)
    vendor = Column(Boolean, default=False)
    client = Column(Boolean, default=False)
    source = Column(String(512), nullable=False, default='manual')
    modified_by = Column(String(128), default=common.get_tester(), nullable=False)
    modified_date = Column(DateTime, default=datetime.utcnow)

    def __repr__(self):
        return self.name + " (" + str(self.email) + ")"


class Phishing(Base):
    """
    hashval -- location_id + scenario + sent_to
    """
    __tablename__ = 'Phishing'

    id = Column(Integer, primary_key=True)
    hashval = Column(String(512), unique=True, nullable=False)
    location_id = Column(Integer, ForeignKey('Location.id', ondelete='cascade'), nullable=False)
    scenario_id = Column(Integer, ForeignKey('PhishingScenario.id', ondelete='cascade'), nullable=False)
    sent_to = Column(String(512), nullable=False)
    smtp_to = Column(String(512), nullable=False)
    data_to = Column(String(512), nullable=False)
    received_response = Column(String(512), nullable=False)
    modified_by = Column(String(128), default=common.get_tester(), nullable=False)
    modified_date = Column(DateTime, default=datetime.utcnow)

    def __repr__(self):
        return self.scenario + " to " + self.sent_to


class PhishingScenario(Base):
    """
    hashval -- scenario + smtp_from + data_from + on_behalf_of + by_way_of
    """
    __tablename__ = 'PhishingScenario'

    id = Column(Integer, primary_key=True)
    hashval = Column(String(512), unique=True, nullable=False)
    scenario = Column(String(512), nullable=False)
    scenario_file = Column(String(512), nullable=False)
    attachment = Column(Text, nullable=True)
    inline_image_path = Column(Text, nullable=True)
    email_server = Column(String(512), nullable=False)
    email_filter_tests_used = Column(String(512), nullable=True)
    send_to_already_phished = Column(Boolean, default=False)
    delay_between_emails = Column(Integer, default=0)
    data_from = Column(String(512), nullable=False)
    smtp_from = Column(String(512), nullable=False)
    priority = Column(Boolean, default=False)
    subject = Column(String(512), nullable=False)
    body = Column(Text, nullable=False)
    signature = Column(Text, nullable=False)
    phish_url = Column(String(512), nullable=True)
    read_receipt_to = Column(String(512), nullable=True)
    on_behalf_of = Column(String(512), nullable=True)
    by_way_of = Column(String(512), nullable=True)
    data_to = Column(String(512), nullable=True)
    spam_score = Column(Text, nullable=True)
    login_username_for_email_server = Column(String(128), nullable=True)
    login_password_for_email_server = Column(String(128), nullable=True)
    modified_by = Column(String(128), default=common.get_tester(), nullable=False)
    modified_date = Column(DateTime, default=datetime.utcnow)

    # used for Cascading delete
    phishing = relationship(Phishing, backref='phishingscenario', cascade="all,delete,delete-orphan", passive_deletes=True)

    #phished = relationship('Phishing', backref='phishingscenario', cascade="all,delete")

    def __repr__(self):
        return self.scenario


class Credential(Base):
    """
    hashval -- domain + username + salted_hash + hash_value + passwd + status + engagement_device_id
    """
    __tablename__ = 'Credential'

    id = Column(Integer, primary_key=True)
    hashval = Column(String(512), unique=True, nullable=False)
    engagementdevice_id = Column(Integer, ForeignKey('EngagementDevice.id', ondelete='cascade'), nullable=True)

    domain = Column(String(512), nullable=True)
    status = Column(String(512), default='current') #could be history1, history2, ...
    service = Column(String(512), default='windows') #windows, ftp, ssh, etc
    username = Column(String(512), nullable=False)
    passwd = Column(String(512), nullable=True)
    salted_hash = Column(Boolean, default=False)
    hash_value = Column(String(512), nullable=True)
    hash_type = Column(String(512), nullable=True)
    amount_of_time_to_crack = Column(Integer, default=0)
    disabled = Column(Boolean, default=False)
    pwdlastset = Column(DateTime, nullable=True)
    pwdnotexpire = Column(Boolean, default=False)
    comment = Column(Text, nullable=True)
    additional = Column(Text, nullable=True)
    da = Column(Boolean, default=False, nullable=True)
    la = Column(Boolean, default=False, nullable=True)
    credential_source = Column(String(512), default='manual')
    validated_credential = Column(Boolean, default=True)
    modified_by = Column(String(128), default=common.get_tester(), nullable=False)
    modified_date = Column(DateTime, default=datetime.utcnow)

    def __repr__(self):
        return self.username + "(" + self.service + ")"

class Result(Base):
    """
    hashval -- scope_id + finding_title + target + port + protocol
    """
    __tablename__ = 'Result'

    id = Column(Integer, primary_key=True)
    hashval = Column(String(512), unique=True, nullable=False)
    engagementdevice_id = Column(Integer, ForeignKey('EngagementDevice.id', ondelete='cascade'), nullable=False)

    finding_title = Column(String(512), nullable=False)
    tool = Column(String(512), nullable=False)
    tool_plugin_id = Column(String(512), nullable=False)
    finding_description = Column(Text, nullable=True)
    finding_remediation = Column(Text, nullable=True)
    finding_cvss = Column(String(256), nullable=True)
    finding_severity = Column(String(256), nullable=True)
    finding_classification = Column(String(256), nullable=True)
    finding_exploits_available = Column(Text, nullable=True)
    finding_patch_publication_date = Column(DateTime, nullable=True)

    target = Column(String(512), nullable=False)
    port = Column(String(50), nullable=False)
    protocol = Column(String(20), nullable=False)
    output = Column(Text, nullable=True)
    tester_output = Column(Text, nullable=True)
    command = Column(String(512), nullable=True)
    start_time = Column(DateTime, nullable=True)
    end_time = Column(DateTime, nullable=True)
    modified_by = Column(String(128), default=common.get_tester(), nullable=False)
    modified_date = Column(DateTime, default=datetime.utcnow)

    def __repr__(self):
        return self.finding_title + " " + self.target


class Log(Base):
    """
    hashval -- start_time + scope_id + target
    target -- can reference a scope_id or an individual entry in that scope id (if scope was an IP range)
    """
    __tablename__ = 'Log'

    id = Column(Integer, primary_key=True)
    hashval = Column(String(512), unique=True, nullable=False)
    scope_id = Column(Integer, ForeignKey('Scope.id', ondelete='cascade'), nullable=False)
    target = Column(Text, nullable=True)
    command = Column(Text, nullable=True)
    start_time = Column(DateTime, nullable=True)
    run_time = Column(DateTime, nullable=True)
    end_time = Column(DateTime, nullable=True)
    pid = Column(String(128), nullable=True)
    children_pids = Column(String(512), nullable=True)
    celery_info = Column(String(512), nullable=True)
    source = Column(String(512), nullable=False)
    blacklisted = Column(Boolean, nullable=True)
    output_filepath = Column(String(512), nullable=True)
    comment = Column(Text, nullable=True)
    allow_rerun = Column(Boolean, default=True)
    queued = Column(Boolean, default=True)
    running = Column(Boolean, default=False)
    failed = Column(Boolean, default=False)
    finished = Column(Boolean, default=False)
    parsed = Column(Boolean, default=False)
    modified_by = Column(String(128), default=common.get_tester(), nullable=False)
    modified_date = Column(DateTime, default=datetime.utcnow)

    def __repr__(self):
        return str(self.start_time) + "-" + self.end_time

class EventMessage(Base):
    """
        hashval -- start_time + scope_id + target
        target -- can reference a scope_id or an individual entry in that scope id (if scope was an IP range)
        """
    __tablename__ = 'EventMessage'

    id = Column(Integer, primary_key=True)
    hashval = Column(String(512), unique=True, nullable=False)
    message = Column(Text, nullable=False)
    modified_by = Column(String(128), default=common.get_tester(), nullable=False)
    modified_date = Column(DateTime, default=datetime.utcnow)

    def __repr__(self):
        return str(self.message)


class TesterDevice(Base):
    """
    hashval -- tester_ip + location
    """
    __tablename__ = 'TesterDevice'

    id = Column(Integer, primary_key=True)
    hashval = Column(String(512), unique=True, nullable=False)
    location_id = Column(Integer, ForeignKey('Location.id', ondelete='cascade'), nullable=False)
    tester_ip = Column(String(512), nullable=False)
    modified_by = Column(String(128), default=common.get_tester(), nullable=False)
    modified_date = Column(DateTime, default=datetime.utcnow)

    def __repr__(self):
        return self.tester_ip


class Webspider(Base):
    """
    hashval - link
    """
    __tablename__ = 'Webspider'

    id = Column(Integer, primary_key=True)
    hashval = Column(String(512), unique=True, nullable=False)
    url = Column(String(512), nullable=False)
    link = Column(String(512), nullable=False)
    completed = Column(Boolean, default=False)
    modified_by = Column(String(128), default=common.get_tester(), nullable=False)
    modified_date = Column(DateTime, default=datetime.utcnow)

    def __repr__(self):
        return self.link


class ForensicLog(Base):
    """
    hashval --
    """
    __tablename__ = 'ForensicLog'

    id = Column(Integer, primary_key=True)
    hashval = Column(String(512), unique=True, nullable=False)
    scope_id = Column(Integer, ForeignKey('Scope.id', ondelete='cascade'), nullable=False)
    suspicion_level = Column(String(50), nullable=False)
    event = Column(String(512), nullable=False)
    forensic_description = Column(Text, nullable=True)
    run_as = Column(String(512), nullable=True)
    run_date = Column(DateTime, nullable=True)
    run_from = Column(String(512), nullable=True)
    parameters = Column(Text, nullable=True)
    succeeded = Column(Boolean, nullable=True)
    object_modified = Column(String(512), nullable=True)
    external_access = Column(Boolean, nullable=True)
    log_name = Column(String(512), nullable=False)
    modified_by = Column(String(128), default=common.get_tester(), nullable=False)
    modified_date = Column(DateTime, default=datetime.utcnow)

    def __repr__(self):
        return self.event

class EngagementDevice(Base):
    """
    hashval -- target_name + scope_id
    """
    __tablename__ = 'EngagementDevice'

    id = Column(Integer, primary_key=True)
    hashval = Column(String(512), unique=True, nullable=False)
    scope_id = Column(Integer, ForeignKey('Scope.id', ondelete='cascade'), nullable=False)
    target_name = Column(String(512), nullable=False)
    target_ip = Column(String(512), nullable=True)
    domain = Column(String(512), nullable=True)
    os = Column(String(512), nullable=True)
    mac = Column(String(512), nullable=True)
    info = Column(String(512), nullable=True)
    av_present = Column(Text, nullable=True)
    services = Column(Text, nullable=True)
    programs = Column(Text, nullable=True)
    accounts = Column(Text, nullable=True)
    source = Column(String(512), nullable=False, default='manual')
    modified_by = Column(String(128), default=common.get_tester(), nullable=False)
    modified_date = Column(DateTime, default=datetime.utcnow)

    # used for Cascading delete
    deviceport = relationship(DevicePort, backref='EngagementDevice', cascade="all,delete,delete-orphan", passive_deletes=True)
    result = relationship(Result, backref='EngagementDevice', cascade="all,delete,delete-orphan", passive_deletes=True)
    credential = relationship(Credential, backref='EngagementDevice', cascade="all,delete", passive_deletes=True)

    def __repr__(self):
        return self.target_name


class Scope(Base):
    """
    hashval -- entry + location_id
    """
    __tablename__ = 'Scope'

    id = Column(Integer, primary_key=True)
    hashval = Column(String(512), unique=True, nullable=False)
    location_id = Column(Integer, ForeignKey('Location.id', ondelete='cascade'), nullable=False)
    original_entry = Column(String(512), nullable=False)
    entry = Column(String(512), nullable=False)
    permission = Column(Boolean, default=True)
    type = Column(String(50), nullable=False)
    open_ip = Column(String(255), nullable=True)
    open_port = Column(String(20), nullable=True)
    information = Column(Text, nullable=True)
    description = Column(Text, nullable=True)
    additional = Column(Text, nullable=True)
    validate = Column(Boolean, default=True)
    modified_by = Column(String(128), default=common.get_tester(), nullable=False)
    modified_date = Column(DateTime, default=datetime.utcnow)

    # used for Cascading delete
    engagementdevices = relationship(EngagementDevice, backref='Scope', cascade="all,delete,delete-orphan", passive_deletes=True)
    recons = relationship(Recon, backref='Scope', cascade="all,delete,delete-orphan", passive_deletes=True)
    logs = relationship(Log, backref='Scope', cascade="all,delete,delete-orphan", passive_deletes=True)
    forensiclogs = relationship(ForensicLog, backref='Scope', cascade="all,delete,delete-orphan", passive_deletes=True)


    def __repr__(self):
        return self.entry

class Location(Base):
    """
    hashval -- name
    """

    __tablename__ = 'Location'

    id = Column(Integer, primary_key=True)
    hashval = Column(String(512), unique=True, nullable=False)
    name = Column(String(255), nullable=False, unique=True)
    modified_by = Column(String(128), default=common.get_tester(), nullable=False)
    modified_date = Column(DateTime, default=datetime.utcnow)

    # used for Cascading delete
    scopes = relationship('Scope', backref='Location', cascade="all,delete,delete-orphan", passive_deletes=True)
    phishing = relationship('Phishing', backref='Location', cascade="all,delete,delete-orphan", passive_deletes=True)

    def __repr__(self):
        return self.name


class Schedule(Base):
    """
    hashval -- name
    """

    __tablename__ = 'Schedule'

    id = Column(Integer, primary_key=True)
    hashval = Column(String(512), unique=True, nullable=False)
    schedule_name = Column(String(255), nullable=False, unique=True)
    enabled = Column(Boolean, default=False)
    rerun_already_run_tasks_for_target = Column(Boolean, default=False)
    modified_by = Column(String(128), default=common.get_tester(), nullable=False)
    modified_date = Column(DateTime, default=datetime.utcnow)

    # used for Cascading delete
    scheduledtasks = relationship('ScheduledTask', backref='Schedule', cascade="all,delete,delete-orphan", passive_deletes=True)

    def __repr__(self):
        return self.schedule_name

class ScheduledTask(Base):
    """
    hashval -- tool_config + ea
    """

    __tablename__ = 'ScheduledTask'

    id = Column(Integer, primary_key=True)
    hashval = Column(String(512), unique=True, nullable=False)
    schedule_id = Column(Integer, ForeignKey('Schedule.id', ondelete='cascade'), nullable=False)
    tool_config = Column(String(255), nullable=False, unique=True)
    earliest_start_time = Column(DateTime, nullable=False)
    stop_running_by_time = Column(DateTime, nullable=True)
    longest_run_time = Column(Integer, primary_key=False, nullable=True)
    minimum_time_necessary_to_run = Column(Integer, primary_key=False, nullable=True) # So will not start if stop_running_by_time is sooner than current time + this time
    log_id = Column(Integer, ForeignKey('Log.id', ondelete='cascade'), nullable=True)
    modified_by = Column(String(128), default=common.get_tester(), nullable=False)
    modified_date = Column(DateTime, default=datetime.utcnow)

    def __repr__(self):
        return self.tool_config