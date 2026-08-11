"""
Application Inversion of Control (IoC) Composition Root Module.

Serves as the exclusive process-wide dependency injection matrix layout for the system.
Handles lazy instantiation of concrete physical engine states, cross-cutting infrastructure adapters, 
data repositories, and business logic services while keeping the object dependency graph fully auditable.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Final

from database.connection import DatabaseConnection, get_db_connection
from infrastructure.notifications.telegram_join_poller import TelegramJoinPoller
from infrastructure.notifications.telegram_notifier import TelegramNotifier
from infrastructure.security.password_hasher import BcryptPasswordHasher
from repositories.alert_repository import AlertRepository
from repositories.blacklist_repository import BlacklistRepository
from repositories.detection_repository import DetectionRepository
from repositories.log_repository import LogRepository
from repositories.model_repository import ModelRepository
from repositories.system_metric_repository import SystemMetricRepository
from repositories.telegram_subscriber_repository import TelegramSubscriberRepository
from repositories.user_repository import UserRepository
from repositories.whitelist_repository import WhitelistRepository
from services.alert_engine import AlertEngine
from services.auth_service import AuthService
from services.csv_analysis_service import CsvAnalysisService
from services.detection_service import DetectionService
from services.firewall_service import FirewallService
from services.ip_list_service import IpListService
from services.model_service import ModelService
from services.model_evaluation_service import ModelEvaluationService
from services.model_metadata_service import ModelMetadataService
from services.monitoring_service import MonitoringService
from services.pcap_analysis_service import PcapAnalysisService


class Container:
    """
    Dependency Injection Container resolving object graphs lazily via process-wide singletons.
    """

    def __init__(self, db: DatabaseConnection | None = None) -> None:
        """
        Initializes the container using a shared context connection bridge.
        """
        self._db: Final[DatabaseConnection] = db or get_db_connection()

        # Cached singleton references for repositories
        self._user_repo: UserRepository | None = None
        self._log_repo: LogRepository | None = None
        self._model_repo: ModelRepository | None = None
        self._detection_repo: DetectionRepository | None = None
        self._alert_repo: AlertRepository | None = None
        self._whitelist_repo: WhitelistRepository | None = None
        self._blacklist_repo: BlacklistRepository | None = None
        self._metric_repo: SystemMetricRepository | None = None
        self._telegram_subscriber_repo: TelegramSubscriberRepository | None = None

        # Cached singleton references for infrastructure components and core services
        self._auth_service: AuthService | None = None
        self._model_service: ModelService | None = None
        self._ip_list_service: IpListService | None = None
        self._alert_engine: AlertEngine | None = None
        self._detection_service: DetectionService | None = None
        self._monitoring_service: MonitoringService | None = None
        self._model_evaluation_service: ModelEvaluationService | None = None
        self._telegram_notifier: TelegramNotifier | None = None
        self._telegram_join_poller: TelegramJoinPoller | None = None
        self._csv_analysis_service: CsvAnalysisService | None = None
        self._pcap_analysis_service: PcapAnalysisService | None = None
        self._firewall_service: FirewallService | None = None
        self._model_metadata_service: ModelMetadataService | None = None

    # =========================================================================
    # Data Access Repositories
    # =========================================================================

    @property
    def user_repository(self) -> UserRepository:
        """Resolves the user identity profile mapping repository access layer."""
        if self._user_repo is None:
            self._user_repo = UserRepository(self._db)
        return self._user_repo

    @property
    def log_repository(self) -> LogRepository:
        """Resolves the immutable diagnostic system audit log repository access layer."""
        if self._log_repo is None:
            self._log_repo = LogRepository(self._db)
        return self._log_repo

    @property
    def model_repository(self) -> ModelRepository:
        """Resolves the machine learning asset registry state repository access layer."""
        if self._model_repo is None:
            self._model_repo = ModelRepository(self._db)
        return self._model_repo

    @property
    def detection_repository(self) -> DetectionRepository:
        """Resolves the inference logs and traffic monitoring repository access layer."""
        if self._detection_repo is None:
            self._detection_repo = DetectionRepository(self._db)
        return self._detection_repo

    @property
    def alert_repository(self) -> AlertRepository:
        """Resolves the deduplicated event alert warning log repository access layer."""
        if self._alert_repo is None:
            self._alert_repo = AlertRepository(self._db)
        return self._alert_repo

    @property
    def whitelist_repository(self) -> WhitelistRepository:
        """Resolves the firewall allowed network resource repository access layer."""
        if self._whitelist_repo is None:
            self._whitelist_repo = WhitelistRepository(self._db)
        return self._whitelist_repo

    @property
    def blacklist_repository(self) -> BlacklistRepository:
        """Resolves the firewall explicitly banned endpoint repository access layer."""
        if self._blacklist_repo is None:
            self._blacklist_repo = BlacklistRepository(self._db)
        return self._blacklist_repo

    @property
    def system_metric_repository(self) -> SystemMetricRepository:
        """Resolves the rolling time-series hardware tracking repository access layer."""
        if self._metric_repo is None:
            self._metric_repo = SystemMetricRepository(self._db)
        return self._metric_repo

    @property
    def telegram_subscriber_repository(self) -> TelegramSubscriberRepository:
        """Resolves the Telegram recipient subscription registry repository access layer."""
        if self._telegram_subscriber_repo is None:
            self._telegram_subscriber_repo = TelegramSubscriberRepository(self._db)
        return self._telegram_subscriber_repo

    # =========================================================================
    # Infrastructure Integration Components
    # =========================================================================

    @property
    def telegram_notifier(self) -> TelegramNotifier:
        """Resolves the system warning event communication broker messaging system client."""
        if self._telegram_notifier is None:
            # Seed runtime overrides (token / legacy chat) persisted in the settings table
            self._telegram_subscriber_repo = self.telegram_subscriber_repository
            runtime_token = self._telegram_subscriber_repo.get_runtime_bot_token()
            runtime_chat_id = self._telegram_subscriber_repo.get_runtime_chat_id()
            self._telegram_notifier = TelegramNotifier(
                bot_token=runtime_token or None,
                chat_id=runtime_chat_id or None,
                subscriber_repository=self._telegram_subscriber_repo,
            )
        return self._telegram_notifier

    @property
    def telegram_join_poller(self) -> TelegramJoinPoller:
        """Resolves the process-wide Telegram join request long-poll listener."""
        if self._telegram_join_poller is None:
            self._telegram_join_poller = TelegramJoinPoller(
                notifier=self.telegram_notifier,
                subscriber_repository=self.telegram_subscriber_repository,
            )
        return self._telegram_join_poller

    # =========================================================================
    # Core Application Business Services
    # =========================================================================

    @property
    def auth_service(self) -> AuthService:
        """Resolves the single access authorization gateway domain operations engine."""
        if self._auth_service is None:
            self._auth_service = AuthService(
                user_repository=self.user_repository,
                password_hasher=BcryptPasswordHasher(),
                log_repository=self.log_repository
            )
        return self._auth_service

    @property
    def ip_list_service(self) -> IpListService:
        """Resolves the network connection zone rule logic filter configuration service."""
        if self._ip_list_service is None:
            self._ip_list_service = IpListService(
                whitelist_repo=self.whitelist_repository,
                blacklist_repo=self.blacklist_repository,
                log_repository=self.log_repository
            )
        return self._ip_list_service

    @property
    def model_service(self) -> ModelService:
        """Resolves the deployment lifecycle tracker machine learning registry service."""
        if self._model_service is None:
            self._model_service = ModelService(
                model_repository=self.model_repository,
                log_repository=self.log_repository
            )
        return self._model_service

    @property
    def model_evaluation_service(self) -> ModelEvaluationService:
        """Resolves the automated model validation profiling and benchmark analysis engine."""
        if self._model_evaluation_service is None:
            self._model_evaluation_service = ModelEvaluationService(
                model_service=self.model_service,
            )
        return self._model_evaluation_service

    @property
    def firewall_service(self) -> FirewallService:
        """Resolves the Windows Firewall rule management and auto-block orchestration service."""
        if self._firewall_service is None:
            self._firewall_service = FirewallService(
                whitelist_repo=self.whitelist_repository,
                blacklist_repo=self.blacklist_repository,
                log_repository=self.log_repository,
            )
        return self._firewall_service

    @property
    def model_metadata_service(self) -> ModelMetadataService:
        """Resolves the model metadata resolution and caching service."""
        if self._model_metadata_service is None:
            self._model_metadata_service = ModelMetadataService()
        return self._model_metadata_service

    @property
    def alert_engine(self) -> AlertEngine:
        """Resolves the incident aggregation and deduplication alert router workflow engine."""
        if self._alert_engine is None:
            self._alert_engine = AlertEngine(
                alert_repository=self.alert_repository,
                ip_list_service=self.ip_list_service,
                notifier=self.telegram_notifier,
                firewall_service=self.firewall_service,
            )
        return self._alert_engine

    @property
    def detection_service(self) -> DetectionService:
        """Resolves the telemetry analysis runtime packet classifier ingestion service."""
        if self._detection_service is None:
            from config.settings import get_settings
            self._detection_service = DetectionService(
                model_service=self.model_service,
                detection_repository=self.detection_repository,
                log_repository=self.log_repository,
                alert_engine=self.alert_engine,
                ip_list_service=self.ip_list_service,
                settings=get_settings(),
                firewall_service=self.firewall_service,
            )
        return self._detection_service

    @property
    def monitoring_service(self) -> MonitoringService:
        """Resolves the dashboard metric counter evaluator infrastructure dashboard driver."""
        if self._monitoring_service is None:
            self._monitoring_service = MonitoringService(
                metric_repository=self.system_metric_repository,
                detection_repository=self.detection_repository,
                alert_repository=self.alert_repository
            )
        return self._monitoring_service

    @property
    def csv_analysis_service(self) -> CsvAnalysisService:
        """Resolves the dataset batch tabular parsing detection driver service."""
        if self._csv_analysis_service is None:
            from config.settings import get_settings
            self._csv_analysis_service = CsvAnalysisService(
                detection_service=self.detection_service,
                model_service=self.model_service,
                settings=get_settings(),
            )
        return self._csv_analysis_service
    @property
    def pcap_analysis_service(self) -> PcapAnalysisService:
        """Resolves the raw wire network pcap capture format analytical decoding service."""
        if self._pcap_analysis_service is None:
            # Encapsulate local runtime import to break execution cycle trees cleanly
            from capture.extractor_factory import get_flow_extractor

            self._pcap_analysis_service = PcapAnalysisService(
                detection_service=self.detection_service,
                flow_extractor=get_flow_extractor(),
                model_service=self.model_service,
            )
        return self._pcap_analysis_service


@lru_cache(maxsize=1)
def get_container() -> Container:
    """
    Resolves the process-wide, memoized IoC Container infrastructure singleton reference.
    """
    return Container()