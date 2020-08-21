/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET NAMES utf8 */;
/*!50503 SET NAMES utf8mb4 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;

CREATE TABLE IF NOT EXISTS `tnblassets` (
  `vcAssetID` varchar(55) NOT NULL,
  `bHasAgent` tinyint(1) DEFAULT NULL,
  `dtCreated` datetime DEFAULT NULL,
  `dtUpdated` datetime DEFAULT NULL,
  `dt1stSeen` datetime DEFAULT NULL,
  `dtLastSeen` datetime DEFAULT NULL,
  `dtFirstScan` datetime DEFAULT NULL,
  `dtLastScan` datetime DEFAULT NULL,
  `dtLastAuthScan` datetime DEFAULT NULL,
  `dtLastLicensedScan` datetime DEFAULT NULL,
  `vcAgentUUID` varchar(55) NOT NULL,
  `vcBIOSid` varchar(55) NOT NULL,
  `vcAgentName` varchar(999) NOT NULL,
  `vcIPv4s` varchar(999) NOT NULL,
  `vcIPv6s` varchar(999) NOT NULL,
  `vcFQDNs` varchar(999) NOT NULL,
  `vcMACAddr` varchar(999) NOT NULL,
  `vcNetbiosNames` varchar(999) NOT NULL,
  `vcOS` varchar(999) NOT NULL,
  `vcHostNames` varchar(999) NOT NULL,
  UNIQUE KEY `idx_tnblassets_vcAssetID` (`vcAssetID`),
  KEY `idx_tnblassets_vcAgentUUID` (`vcAgentUUID`),
  KEY `idx_tnblassets_vcBIOSid` (`vcBIOSid`),
  KEY `idx_tnblassets_vcAgentName` (`vcAgentName`),
  KEY `idx_tnblassets_vcFQDNs` (`vcFQDNs`),
  KEY `idx_tnblassets_vcNetbiosNames` (`vcNetbiosNames`),
  KEY `idx_tnblassets_vcHostNames` (`vcHostNames`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

/*!40101 SET SQL_MODE=IFNULL(@OLD_SQL_MODE, '') */;
/*!40014 SET FOREIGN_KEY_CHECKS=IF(@OLD_FOREIGN_KEY_CHECKS IS NULL, 1, @OLD_FOREIGN_KEY_CHECKS) */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
