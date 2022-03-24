import os
import sys
from sqlalchemy import Column, ForeignKey, Integer, String, Float, DateTime, Text, Boolean
from sqlalchemy.orm import relationship

from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()
 
class Experiment(Base):
    __tablename__ = 'experiments'

    id = Column('id', String(200), primary_key=True)

    # Experiment id is the md5 of the analysis config path + 
    # the poc_path (this is unique amond ALL the experiments.
    fuzzer_id = Column('fuzzer_id', Integer)
    poc_path = Column('poc_path', Text)
    poc_tracing_total_time = Column('poc_tracing_total_time', Float)
    exp_total_time = Column('exp_total_time', Float)
    vuln = Column('vuln', String(250))
    errors = Column('errors', String(500))

class ExperimentResult(Base):
    __tablename__ = 'experiments_results'

    # Result is unique in all the experiments and it's the md5
    # of vuln_name + exp_primitive + poc_name + config. <-- want to test entire space
    # vuln_name + exp_primitive  <-- want to stop at the first vuln proven by an exp_primitive.
    id = Column('id',  String(300), primary_key=True)
    vuln = Column('vuln', String(20), nullable=False) # overlap, bad_alloc, arb_write, etc...
    exploit_primitive =  Column('exploit_primitive', String(20), nullable=False) # fake_free, double_free, ...
    poc_path = Column('poc_path', Text, nullable=False) 
    depth = Column('depth', Integer)
    tracing_cmd = Column('tracing_cmd', Text, nullable=False) #command to launch to verify the poc.
    concretize_cmd = Column('concr_cmd', Text, nullable=False) #command to launch to verify the poc.
    tenebraug_cmd = Column('tenebraug_cmd', Text, nullable=False) #command to launch to verify the poc.
    verified = Column('verified', Boolean, default=False) #command to launch to verify the poc.
    false_positive = Column('false_positive', Boolean, default=False) #command to launch to verify the poc.


class ExperimentsMetadata(Base):
    __tablename__ = 'metadata_experiments'

    id = Column('id', Integer, primary_key=True)
    num_timeouts = Column('num_timeouts', Integer)
    num_unconstrained = Column('num_unconstrained', Integer)
    num_state_explosions = Column('num_state_explosions', Integer)
    num_out_of_memory = Column('num_out_of_memory', Integer)
    num_loopseer_intervention = Column('num_loopseer_intervention', Integer)
    vuln_total = Column('vuln_total', Integer)
    start_time = Column('start_time', DateTime) 
    end_time = Column('end_time', DateTime)
