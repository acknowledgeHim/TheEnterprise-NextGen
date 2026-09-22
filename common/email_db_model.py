import os
from datetime import datetime
from sqlalchemy import create_engine
from sqlalchemy import Table, Column, Integer, String, Date, DateTime, ForeignKey, Boolean, Text
from sqlalchemy.orm import relationship, backref
from sqlalchemy.ext.declarative import declarative_base
from common import common

Base = declarative_base()

def initialize_email_db(sqlite_file):
    engine = create_engine('sqlite:///' + sqlite_file, connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)


class FlaskUser(Base):
    """
    User / Pass for Flask (Web App)
    """
    __tablename__ = 'flaskuser'


    id = Column(Integer, primary_key=True)
    hashval = Column(String(512), unique=True, nullable=False)
    username = Column(String(512), nullable=False)
    passwd = Column(String(512), nullable=False)
    modified_by = Column(String(128), default=common.get_tester(), nullable=False)
    modified_date = Column(DateTime, default=datetime.utcnow)

    def __repr__(self):
        return self.username


class EmailEvent(Base):
    """
    hashval -- event + start_or_end
    """
    __tablename__ = 'emailevent'

    id = Column(Integer, primary_key=True)
    hashval = Column(String(512), unique=True, nullable=False)
    event = Column(String(512), nullable=False)
    subject = Column(Text, nullable=False)
    tester_msg = Column(Text, nullable=True)
    corp_msg = Column(Text, nullable=True)
    client_msg = Column(Text, nullable=True)
    start_or_end = Column(String(512), nullable=False, default='end')
    modified_by = Column(String(128), default=common.get_tester(), nullable=False)
    modified_date = Column(DateTime, default=datetime.utcnow)

    def __repr__(self):
        return self.event + " " + self.start_or_end


class OSExploitationPath(Base):
    """
    hashval -- os + source + os_exploit_name
    """
    __tablename__ = 'osexploitationpath'

    id = Column(Integer, primary_key=True)
    hashval = Column(String(512), unique=True, nullable=False)
    os_exploit_name = Column(String(512), nullable=False)
    os = Column(String(512), nullable=False)
    exploit_code = Column(Text, nullable=True)
    source = Column(String(512), nullable=True)
    severity = Column(String(512), nullable=True)
    disruptive = Column(Boolean, default=True)
    description = Column(Text, nullable=True)
    conditions = Column(Text, nullable=True)
    modified_by = Column(String(128), default=common.get_tester(), nullable=False)
    modified_date = Column(DateTime, default=datetime.utcnow)

    def __repr__(self):
        return self.os_exploit_name + "(" + self.os + ")"

class ServiceExploitationPath(Base):
    """
    hashval -- service + source + service_exploit_name
    """
    __tablename__ = 'serviceexploitationpath'

    id = Column(Integer, primary_key=True)
    hashval = Column(String(512), unique=True, nullable=False)
    service_exploit_name = Column(String(512), nullable=False)
    service = Column(String(512), nullable=False)
    version = Column(String(512), nullable=False)
    exploit_code = Column(Text, nullable=True)
    source = Column(String(512), nullable=True)
    severity = Column(String(512), nullable=True)
    disruptive = Column(Boolean, default=True)
    description = Column(Text, nullable=True)
    conditions = Column(Text, nullable=True)
    modified_by = Column(String(128), default=common.get_tester(), nullable=False)
    modified_date = Column(DateTime, default=datetime.utcnow)

    def __repr__(self):
        return self.service_exploit_name + "(" + self.service + " " + self.version + ")"

class NetworkExploitationPath(Base):
    """
    hashval -- service + source + network_exploit_name
    """
    __tablename__ = 'networkexploitationpath'

    id = Column(Integer, primary_key=True)
    hashval = Column(String(512), unique=True, nullable=False)
    network_exploit_name = Column(String(512), nullable=False)
    service = Column(String(512), nullable=False)
    version = Column(String(512), nullable=True)
    exploit_code = Column(Text, nullable=True)
    source = Column(String(512), nullable=True)
    severity = Column(String(512), nullable=True)
    disruptive = Column(Boolean, default=True)
    description = Column(Text, nullable=True)
    conditions = Column(Text, nullable=True)
    modified_by = Column(String(128), default=common.get_tester(), nullable=False)
    modified_date = Column(DateTime, default=datetime.utcnow)

    def __repr__(self):
        return self.network_exploit_name

class PrivilegeEscallationPath(Base):
    """
    hashval -- exploit_source + privesc_name
    """
    __tablename__ = 'privilegeescallationpath'

    id = Column(Integer, primary_key=True)
    hashval = Column(String(512), unique=True, nullable=False)
    privesc_name = Column(String(512), nullable=False)
    exploit_code = Column(Text, nullable=True)
    source = Column(String(512), nullable=True)
    severity = Column(String(512), nullable=True)
    disruptive = Column(Boolean, default=True)
    description = Column(Text, nullable=True)
    conditions = Column(Text, nullable=True)
    modified_by = Column(String(128), default=common.get_tester(), nullable=False)
    modified_date = Column(DateTime, default=datetime.utcnow)

    def __repr__(self):
        return self.privesc_name