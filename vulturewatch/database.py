"""Módulo de banco de dados para controle de estado"""
import os
from datetime import datetime
from sqlalchemy import create_engine, Column, String, DateTime, Integer, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from typing import Optional, List
import json
from .security import validate_database_url

Base = declarative_base()


class AlertSent(Base):
    """Modelo para alertas já enviados"""
    __tablename__ = "alerts_sent"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    cve_id = Column(String, nullable=False, index=True)
    component = Column(String, nullable=False)
    version_range = Column(String)
    first_seen_at = Column(DateTime, default=datetime.utcnow)
    last_notified_at = Column(DateTime, default=datetime.utcnow)
    channels_notified = Column(JSON, default=list)  # ["slack", "telegram"]
    status = Column(String, default="new")  # new, acknowledged, ignored
    alert_metadata = Column("metadata", JSON, default=dict)  # Informações extras (coluna chamada 'metadata' no DB)
    
    def __repr__(self):
        return f"<AlertSent(cve_id={self.cve_id}, component={self.component}, status={self.status})>"


class Database:
    """Gerencia conexão e operações do banco de dados"""
    
    def __init__(self, config: dict):
        db_type = config.get("type", "sqlite")
        
        if db_type == "sqlite":
            db_path = config.get("path", "./vulturewatch.db")
            self.engine = create_engine(f"sqlite:///{db_path}", echo=False)
        elif db_type == "postgresql":
            db_url = config.get("url") or os.getenv("DATABASE_URL")
            if not db_url:
                raise ValueError("DATABASE_URL não configurada para PostgreSQL")
            # Valida URL do banco de dados
            if not validate_database_url(db_url):
                raise ValueError(f"URL de banco de dados inválida ou suspeita: {db_url}")
            self.engine = create_engine(db_url, echo=False)
        else:
            raise ValueError(f"Tipo de banco não suportado: {db_type}")
        
        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine)
    
    def get_session(self):
        """Retorna uma sessão do banco"""
        return self.Session()
    
    def alert_already_sent(self, cve_id: str, component: str) -> bool:
        """Verifica se alerta já foi enviado"""
        session = self.get_session()
        try:
            alert = session.query(AlertSent).filter_by(
                cve_id=cve_id,
                component=component,
                status="new"
            ).first()
            return alert is not None
        finally:
            session.close()
    
    def mark_alert_sent(self, cve_id: str, component: str, version_range: str, 
                       channels: List[str], metadata: dict = None):
        """Marca alerta como enviado"""
        session = self.get_session()
        try:
            # Verifica se já existe
            alert = session.query(AlertSent).filter_by(
                cve_id=cve_id,
                component=component
            ).first()
            
            if alert:
                # Atualiza existente
                alert.last_notified_at = datetime.utcnow()
                alert.channels_notified = list(set(alert.channels_notified + channels))
                if metadata:
                    alert.alert_metadata.update(metadata)
            else:
                # Cria novo
                alert = AlertSent(
                    cve_id=cve_id,
                    component=component,
                    version_range=version_range,
                    channels_notified=channels,
                    alert_metadata=metadata or {}
                )
                session.add(alert)
            
            session.commit()
        finally:
            session.close()
    
    def acknowledge_alert(self, cve_id: str, component: str):
        """Marca alerta como reconhecido"""
        session = self.get_session()
        try:
            alert = session.query(AlertSent).filter_by(
                cve_id=cve_id,
                component=component
            ).first()
            
            if alert:
                alert.status = "acknowledged"
                session.commit()
        finally:
            session.close()
    
    def ignore_alert(self, cve_id: str, component: str):
        """Marca alerta como ignorado"""
        session = self.get_session()
        try:
            alert = session.query(AlertSent).filter_by(
                cve_id=cve_id,
                component=component
            ).first()
            
            if alert:
                alert.status = "ignored"
                session.commit()
        finally:
            session.close()

