-- MySQL dump 10.13  Distrib 8.0.16, for Win64 (x86_64)
--
-- Host: localhost    Database: fourleavesshoe2
-- ------------------------------------------------------
-- Server version	8.0.16

create database fourleavesshoe3;
use fourleavesshoe3;

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
 SET NAMES utf8 ;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `danhmuc`
--

DROP TABLE IF EXISTS `danhmuc`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
 SET character_set_client = utf8mb4 ;
CREATE TABLE `danhmuc` (
  `madanhmuc` int(11) NOT NULL AUTO_INCREMENT,
  `TenDanhMuc` varchar(50) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci DEFAULT NULL,
  `TinhTrang` int(11) DEFAULT NULL,
  PRIMARY KEY (`madanhmuc`)
) ENGINE=InnoDB AUTO_INCREMENT=12 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `danhmuc`
--

LOCK TABLES `danhmuc` WRITE;
/*!40000 ALTER TABLE `danhmuc` DISABLE KEYS */;
INSERT INTO `danhmuc` VALUES (1,'Sneakers',1),(2,'Loafers',1),(3,'Boots',1),(4,'Sandals',0),(5,'Oxfords',1),(6,'Flats',1),(7,'Espadrilles',1),(8,'Athletic Shoes',1),(9,'Mules',1),(10,'Ballet Flats',1),(11,'smoop12',0);
/*!40000 ALTER TABLE `danhmuc` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `phuongthuc_thanhtoan`
--

DROP TABLE IF EXISTS `phuongthuc_thanhtoan`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
 SET character_set_client = utf8mb4 ;
CREATE TABLE `phuongthuc_thanhtoan` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `Ten` varchar(100) DEFAULT NULL,
  `MoTa` varchar(100) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=4 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `phuongthuc_thanhtoan`
--

LOCK TABLES `phuongthuc_thanhtoan` WRITE;
/*!40000 ALTER TABLE `phuongthuc_thanhtoan` DISABLE KEYS */;
INSERT INTO `phuongthuc_thanhtoan` VALUES (1,'Home Delivery (COD)','Chỉ nhận tiền khi lấy được hàng'),(2,'Bank card payment','Giao dịch qua thẻ credit hoặc debit của ngân hàng');
/*!40000 ALTER TABLE `phuongthuc_thanhtoan` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `sanpham`
--

DROP TABLE IF EXISTS `sanpham`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
 SET character_set_client = utf8mb4 ;
CREATE TABLE `sanpham` (
  `masp` int(11) NOT NULL AUTO_INCREMENT,
  `TenSanPham` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci DEFAULT NULL,
  `SoLuong` int(11) DEFAULT NULL,
  `DaBan` int(11) DEFAULT NULL,
  `GiaTien` int(11) DEFAULT NULL,
  `MaVatLieu` int(11) DEFAULT NULL,
  `MoTa` varchar(500) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci DEFAULT NULL,
  `Anh` varchar(500) DEFAULT NULL,
  `NgayTao` date DEFAULT NULL,
  `TinhTrang` int(11) DEFAULT NULL,
  `GiamGia` int(11) DEFAULT NULL,
  `MaDanhMuc` int(11) DEFAULT NULL,
  PRIMARY KEY (`masp`),
  KEY `FK_SANPHAM_DM_DM_idx` (`MaDanhMuc`),
  KEY `FK_SANPHAM_HV_HV_idx` (`MaVatLieu`),
  CONSTRAINT `FK_SANPHAM_DM_DM` FOREIGN KEY (`MaDanhMuc`) REFERENCES `danhmuc` (`madanhmuc`) ON DELETE SET NULL ON UPDATE CASCADE,
  CONSTRAINT `FK_SANPHAM_HV_THV` FOREIGN KEY (`MaVatLieu`) REFERENCES `vatlieu` (`mavatlieu`)
) ENGINE=InnoDB AUTO_INCREMENT=123 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `sanpham`
--

LOCK TABLES `sanpham` WRITE;
/*!40000 ALTER TABLE `sanpham` DISABLE KEYS */;
INSERT INTO `sanpham` VALUES (1,'Lacoste Men\'s Gripshot Sneaker',30,48,49,4,'100% Cotton, Imported, Synthetic sole,Shaft measures approximately low-top from arch, Canvas and synthetic uppers, Rubber outsole, Canvas linings, Embroidered green crocodile branding on the quarter','https://m.media-amazon.com/images/I/71Ps5Pf7OQL._AC_UX575_.jpg','2023-04-24',1,10,1),(2,'Cole Haan Men\'s Grand Crosscourt II Sneakers',45,72,66,3,'100% Leather, Imported, Rubber sole, Shaft measures approximately low-top from arch, Sleek and simple, the Grand Crosscourt Sneaker is the perfect way to add some tailored casual style to your every day look. Classic sport inspired oxford in leather, suede or textile uppers, Injection molded outsole with rubber pods in heel and forefoot, Grand 360 Design and Engineering comfort technology, Textile lined','https://m.media-amazon.com/images/I/71hi7LCKXJL._AC_UX575_.jpg','2023-03-22',1,20,1),(3,'Sand Suede Loafers',70,94,259,2,'Rigid heel counter crafted to support your rear-foot. 30mm heel height. Suede upper, leather sole with a stitched rubber outsole, leather lining, leather lined footbed.','https://res.cloudinary.com/baredfootwear/image/fetch/f_auto/https://cdn.shopify.com/s/files/1/0322/6841/9208/products/Electrum_SandSuede_211203_02_1000x1000.jpg?v=1638491362','2023-03-23',1,15,2),(4,'Charcoal Nubuck Boat Shoes',65,67,286,1,'Recycled cotton laces. Two-eyelet lacing system for an adjustable fit. 12mm heel height. Nubuck upper, natural & synthetic rubber outsole, leather lining and a leather-lined footbed. Cement construction.','https://res.cloudinary.com/baredfootwear/image/fetch/f_auto/https://cdn.shopify.com/s/files/1/0322/6841/9208/products/Polonium_CharcoalNubuck_210929_02_1000x1000.jpg?v=1634612764','2023-01-23',1,0,2),(5,'Dr. Martens Women\'s Combs W Combat Boot',80,55,70,2,'Imported. Rubber sole. Shaft measures approximately mid-calf from arch. Platform measures approximately 1 inches. Extra-tough nylon. Welted construction.','https://m.media-amazon.com/images/I/81TxIL257QL._AC_UX395_.jpg','2023-02-12',1,0,3),(6,'Rocket Dog Women\'s Sheriff Boot',115,134,50,3,'Synthetic Rubber sole. Shaft measures approximately 8 from arch. Heel measures approximately 2.5\". Boot opening measures approximately 13.5\" around. Western-inspired style boot. ','https://m.media-amazon.com/images/I/91ABavds1pL._AC_UY395_.jpg','2023-03-14',1,0,3),(7,'Skechers Women\'s On-The-go 600-Brilliancy Sport Sandal',0,34,36,5,'Textile. Imported. Rubber sole. Platform measures approximately 0.75 inches. Lightweight, responsive 5Gen cushioning. Sketchers Goga Max high rebound insole for maximum comfort. Adjustable straps for secure fit. Soft heathered fabric upper.','https://m.media-amazon.com/images/I/71A7qxaUDCL._AC_UX395_.jpg','2023-04-04',1,0,4),(8,'BASS OUTDOOR Women\'s Trail Sandal Hiking Shoe',115,32,69,2,'Rubber sole. Cushioned and contoured comfort footbed. Adjustable velcro closure.','https://m.media-amazon.com/images/I/71x0c6JKthL._AC_UY500_.jpg','2023-01-13',1,0,4),(9,'Clarks Tilden Cap',55,27,58,1,'100% Leather. Imported. Thermoplastic Elastomers sole. Heel measures approximately 0.98\". These smart men\'s shoes with a square cap toe toe are crafted from a premium leather. Stretch Gore Panels for a Flexible Fit. Ortholite footbed that softens impact and wicks away moisture.','https://m.media-amazon.com/images/I/81zqrHuWkZL._AC_UY395_.jpg','2023-05-01',1,0,5),(10,'Steve Madden Men\'s Harpoon Oxford',100,15,70,4,'100% Leather. Synthetic sole. Leather upper with double-stitched overlay detail. Textile lining. Synthetic outsole. Lace-up closure. Available in extended sizes (Men\'s 14-17 M US).','https://m.media-amazon.com/images/I/71gMH0EIW7L._AC_UY500_.jpg','2023-04-15',1,0,5),(11,'Amazon Essentials Women\'s Belice Ballet Flat',100,44,23,4,'100% Synthetic. Imported. Synthetic sole. Shaft measures approximately Low-top from arch. Classic and versatile ballet flat designed for daily wear and superior fit. Casual silhouette with round toe shape and flattering profile. Soft, faux leather upper with gently elasticized topline featuring a flexible outsole for amazing comfort.','https://m.media-amazon.com/images/I/61LXr87tpJL._AC_UX395_.jpg','2022-09-12',1,0,6),(12,'Bloch Women\'s Nashira Ballet Flat',150,69,125,2,'Imported. Thermoplastic Polyurethane sole. Sizing: We recommend choosing ½ size up from your regular US street shoe size. (Shoes and boxes will display the corresponding European shoe size). Nappa leather upper with matte finish. ','https://m.media-amazon.com/images/I/61rt2HvIGzL._AC_UX395_.jpg','2022-09-15',1,0,6),(13,'TOMS Women\'s, Alpargata Rope Recycled Espadrille Slip-On',20,14,50,3,'Fabric-and-synthetic. Imported. Manmade sole. Lightweight canvas upper made from 50% recycled cotton. Cushioned insole.','https://m.media-amazon.com/images/I/61DX+gfgkpL._AC_UY395_.jpg','2022-12-21',1,0,7),(14,'Lauren by Ralph Lauren Women\'s Adult Espadrille',80,41,100,2,'Imported. Rubber sole. Slip-on styling. Polished \"LRL\" metal logo at the vamp. Padded forepart and sock patch with a foil-printed “Lauren Ralph Lauren” logo.','https://m.media-amazon.com/images/I/71uWDaFq2DL._AC_UX395_.jpg','2022-10-04',1,0,7),(15,'Brooks Women\'s Ghost 14 Neutral Running Shoe',50,48,100,3,'BALANCED, SOFT CUSHIONING: BioMoGo DNA and DNA LOFT cushioning work together to provide a just-right softness underfoot without losing responsiveness and durability - yet it feels lighter than ever. DNA LOFT now makes up the entire midsole, for a softer, smoother, ride.','https://m.media-amazon.com/images/I/81caeKAttiL._AC_UY395_.jpg','2022-11-13',1,0,8),(16,'Nike Women\'s Basketball',90,52,170,5,'Rubber sole. 100% Authentic. ','https://m.media-amazon.com/images/I/51mNlxDSv1L._AC_UY395_.jpg','2022-12-04',1,0,8),(17,'Easy Spirit Women\'s TRAVELTIME295 Mule',60,73,42,5,'80% Suede, 20% Fabric. Imported. Rubber sole. Shaft measures approximately not_applicable from arch. Removable insole. Flexible Durable Outsole. ','https://m.media-amazon.com/images/I/71pL+M604iL._AC_UX395_.jpg','2022-10-03',1,0,9),(18,'Naturalizer Women\'s, Kayden Mule',25,112,53,5,'100%Cotton. Manmade sole. Manmade or manmade/fabric upper. 1/2 inch heel. Contour+ technology for a premium fit and all-day comfort experience.','https://m.media-amazon.com/images/I/61Q5+2BCvOL._AC_UX500_.jpg','2022-12-23',1,0,9),(19,'Amazon Essentials Women\'s Buckle Mule',110,54,23,5,'Imported. Faux Leather sole. Shaft measures approximately not_applicable from arch. Faux leather upper with faux leather lining.','https://m.media-amazon.com/images/I/713pFX6aOgL._AC_UX395_.jpg','2022-11-24',1,10,9),(20,'Franco Sarto Womens Sela Slip On Pointed Toe Mule , Black, 8.5',70,38,68,4,'100% Leather. Imported. Manmade sole. Shaft measures approximately not_applicable from arch. Women\'s slip on mules features a leather or faux leather upper and cut-away lip detail for a sophisticated style.','https://m.media-amazon.com/images/I/71U+sII7RgL._AC_UX395_.jpg','2022-10-25',1,0,9),(21,'Jessica Simpson Women\'s Mandalaye Square Toe Ankle-Wrap Ballet Flats',15,92,55,2,'Vegan. Made in USA or Imported. Synthetic sole. Shaft measures approximately not_applicable from arch. Synthetic lining. Target gender: female.','https://m.media-amazon.com/images/I/61GN70kTv5L._AC_UY395_.jpg','2022-11-12',1,0,10),(22,'Clarks Women\'s Sara Ballet Flat',35,87,100,3,'100% Leather. Made in the USA or Imported. Thermoplastic Elastomers sole. Heel measures approximately 0.59\". A true classic: chic, simple and timeless. Elegant, femine ballerina. 6\" heel height.','https://m.media-amazon.com/images/I/61cjw8dYEML._AC_UX395_.jpg','2022-11-13',1,0,10),(23,'Naturalizer Women\'s, Flexy Flat',55,13,45,1,'100%Cotton. Imported. Leather sole. Shaft measures approximately not_applicable from arch. Leather or fabric upper. Slip on style for an easy on and off.','https://m.media-amazon.com/images/I/61AtJOjUKIL._AC_UX395_.jpg','2022-10-03',1,0,10),(24,'Bloch Women\'s Cassiopeia Ballet Flat',10,30,124,2,'Imported. Thermoplastic Polyurethane sole. Sizing: We recommend choosing ½ size up from your regular US street shoe size. (Shoes and boxes will display the corresponding European shoe size). Two-tone leather upper with matte finish. TPU outsole and leather lining.','https://m.media-amazon.com/images/I/61QOsgB9Y7L._AC_UX395_.jpg','2022-12-16',1,0,10);
/*!40000 ALTER TABLE `sanpham` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `sysdiagrams`
--

DROP TABLE IF EXISTS `sysdiagrams`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
 SET character_set_client = utf8mb4 ;
CREATE TABLE `sysdiagrams` (
  `name` varchar(160) NOT NULL,
  `principal_id` int(11) NOT NULL,
  `diagram_id` int(11) NOT NULL,
  `version` int(11) DEFAULT NULL,
  `definition` longblob,
  PRIMARY KEY (`diagram_id`),
  UNIQUE KEY `UK_principal_name` (`principal_id`,`name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `sysdiagrams`
--

LOCK TABLES `sysdiagrams` WRITE;
/*!40000 ALTER TABLE `sysdiagrams` DISABLE KEYS */;
/*!40000 ALTER TABLE `sysdiagrams` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `taikhoan`
--

DROP TABLE IF EXISTS `taikhoan`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
 SET character_set_client = utf8mb4 ;
CREATE TABLE `taikhoan` (
  `matk` int(11) NOT NULL AUTO_INCREMENT,
  `TaiKhoan` varchar(50) DEFAULT NULL,
  `MatKhau` varchar(500) DEFAULT NULL,
  `NgayTao` date DEFAULT NULL,
  `MaVaiTro` int(11) DEFAULT NULL,
  `TinhTrang` int(11) DEFAULT NULL,
  `password_reset_token` varchar(100) DEFAULT NULL,
  PRIMARY KEY (`matk`),
  UNIQUE KEY `UQ__TaiKhoan__D5B8C7F039955D82` (`TaiKhoan`),
  UNIQUE KEY `UQ__TaiKhoan__D5B8C7F08B36CD08` (`TaiKhoan`),
  UNIQUE KEY `UQ__TaiKhoan__D5B8C7F0C701C38D` (`TaiKhoan`),
  UNIQUE KEY `UQ__TaiKhoan__D5B8C7F0AC18A387` (`TaiKhoan`),
  UNIQUE KEY `password_reset_token` (`password_reset_token`),
  UNIQUE KEY `taikhoan_unique` (`TaiKhoan`),
  KEY `FK_TAIKHOAN_TK_VT_idx` (`MaVaiTro`),
  CONSTRAINT `FK_TAIKHOAN_TK_VT` FOREIGN KEY (`MaVaiTro`) REFERENCES `vaitro` (`mavaitro`) ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=44 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `taikhoan`
--

LOCK TABLES `taikhoan` WRITE;
/*!40000 ALTER TABLE `taikhoan` DISABLE KEYS */;
INSERT INTO `taikhoan` VALUES (12,'zafu','$2a$10$yggrV/i6HxymQQVILSLec.2qxBaGXUjXfbQkKbmump3OhVSIA/YGS','2023-04-03',3,1,NULL),(14,'giaphuvip','$2a$10$/CSQMc3viQHnudGGxMGIuOf0yID4ZDJ96dXyHUymv5V6bQeb4FwJ6','2023-04-03',3,1,NULL),(15,'real','$2a$10$H6AUfmzm6CjpJ.W5xRmynO3MSCl04YCO7IIOgM1BVe4sXmo2hr4iG','2023-04-04',3,1,NULL),(17,'CongFung','$2a$10$zwsmraH066/HqTXoUsO4iuJdpAmBnMWZ4yGCUfXW7vpPR0N/MO3Hm','2023-04-12',3,1,NULL),(18,'sangpro123','$2a$10$53j8.1b5P91iEcifTX5tfuoGdriDXmoRLpTmVwtbCS0I7olSGwavG','2023-04-12',3,1,NULL),(19,'zafu1','$2a$10$PPNRAfQIfxoh9xB47a7tt.bfQz/pHh0sr7UqBvo9X6pOofPPIMt92','2023-06-14',2,0,NULL),(22,'tk1','$2a$10$Wm9gBBpP3PG9Sxa6.a5st.JSta..P/fIUKXKtWaY5dbProjCmaaru','2023-04-22',3,1,NULL),(23,'test1','$2a$10$OhxT/xU1g5YpffZjeHmRW.OutiA3hSzy5qnk/OTX1BU5FTLU/vLHm','2023-04-24',2,1,NULL),(28,'temp1','$2a$10$O6KRhhBfgjHZi3KYjwsaA.8gPuTACD8A1kiY7/EyW2v2XXpx60NYq','2023-04-24',2,1,NULL),(29,'temp2','123','2023-04-23',2,1,NULL),(30,'me','123','2023-04-23',2,1,NULL),(31,'admin','$2a$10$cWjk2hCTjzzeYmLh52Fa8eQaZHioWfRHsloxccXaDCqYvoIkqOLqW','2023-04-28',1,1,NULL),(32,'test2','123',NULL,2,1,NULL),(33,'vovanduc','$2a$10$GdeMnMTomMHy0ISFwi7vpOyn7Dbm8eHVYnIQICxTqiVGFzVeSQ70W','2023-05-09',3,1,NULL),(34,'hellobro','$2a$10$ct6ICfNh9Yw/.zG5BBHay.0Li1S4XwrruyHxX4bvc8he8yX9ohgMC','2023-05-12',3,1,NULL),(35,'duc50','$2a$10$k1Q69SaSIxhIxu9Aukq5he2KTD4an0.1aJWzXfnAyZGn5BwrqbMLy','2023-05-22',3,1,NULL),(36,'duc88','$2a$10$RgjPU5Z/sJ8O9RBYbuOjIOrFgV1MZHm6XPeuMvs06k2vSc3yaObXW','2023-05-29',3,1,NULL),(37,'duc1001','$2a$10$.6HbyaL0X9NrS6w6GsdwZu5a9u4NSCx7NAgLvjIvK1T8hroZD9Sbq','2023-06-17',2,1,NULL),(39,'duc89','$2a$10$zDvL00VNJwZhNxf4TzjOouC.LaWpwB.TUpYDwbWAJ0.r1k.Yo9kZ2','2023-06-17',3,1,NULL),(40,'duc91','$2a$10$K5C7yQYNhENns.nyyG2ox.kBBCyLCsFqQhriImthe8zYIeHSNwxDe','2023-06-17',3,1,NULL),(41,'nndand','$2a$10$b9ZE9amDQrlzezsSHCJ3..w6B3CzHzRZL3EvWM4auLDKDcYCgPmQG','2023-06-17',3,1,NULL),(42,'duc93','$2a$10$ZvFijRewGEZmmUHMqPtzAONnmmNm3eDkREUQlYjS0TC8QZ.rwhZDu','2023-06-17',3,1,NULL),(43,'nhi88','$2a$10$4BrvmxXX7zmtT8Drsh/9GeDaXvLag3OB6twiik3nwgoeKW.fJDXpy','2023-06-17',3,1,NULL);
/*!40000 ALTER TABLE `taikhoan` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `vaitro`
--

DROP TABLE IF EXISTS `vaitro`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
 SET character_set_client = utf8mb4 ;
CREATE TABLE `vaitro` (
  `mavaitro` int(11) NOT NULL AUTO_INCREMENT,
  `TenVaiTro` varchar(50) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci DEFAULT NULL,
  PRIMARY KEY (`mavaitro`)
) ENGINE=InnoDB AUTO_INCREMENT=4 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `vaitro`
--

LOCK TABLES `vaitro` WRITE;
/*!40000 ALTER TABLE `vaitro` DISABLE KEYS */;
INSERT INTO `vaitro` VALUES (1,'Admin'),(2,'Nhan Vien'),(3,'KhachHang');
/*!40000 ALTER TABLE `vaitro` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `vatlieu`
--

DROP TABLE IF EXISTS `vatlieu`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
 SET character_set_client = utf8mb4 ;
CREATE TABLE `vatlieu` (
  `mavatlieu` int(11) NOT NULL AUTO_INCREMENT,
  `TenVatLieu` varchar(50) CHARACTER SET utf8 COLLATE utf8_general_ci DEFAULT NULL,
  `MoTa` varchar(100) DEFAULT NULL,
  `TinhTrang` int(11) DEFAULT NULL,
  PRIMARY KEY (`mavatlieu`),
  UNIQUE KEY `TenVatLieu_UNIQUE` (`TenVatLieu`)
) ENGINE=InnoDB AUTO_INCREMENT=12 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `vatlieu`
--

LOCK TABLES `vatlieu` WRITE;
/*!40000 ALTER TABLE `vatlieu` DISABLE KEYS */;
INSERT INTO `vatlieu` VALUES (1,'Leather','Durable and versatile',1),(2,'Suede','Soft and velvety',1),(3,'Canvas','Lightweight and breathable',1),(4,'Mesh','Lightweight and breathable synthetic',1),(5,'Synthetic Leather','Man-made',1),(6,'Rubber','Flexible and waterproof ',1),(7,'EVA','Lightweight and cushioning foam',1),(8,'Knit','Stretchy and breathable',1),(9,'Gore-Tex','Waterproof and breathable membrane',1),(10,'Patent Leather','Glossy and shiny leather',1),(11,'Lek','Nothing',0);
/*!40000 ALTER TABLE `vatlieu` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `khachhang`
--

DROP TABLE IF EXISTS `khachhang`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
 SET character_set_client = utf8mb4 ;
CREATE TABLE `khachhang` (
  `makh` int(11) NOT NULL AUTO_INCREMENT,
  `HoTen` varchar(50) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci DEFAULT NULL,
  `NgaySinh` date DEFAULT NULL,
  `GioiTinh` varchar(50) DEFAULT NULL,
  `DiaChi` varchar(200) DEFAULT NULL,
  `ThanhPho` varchar(100) DEFAULT NULL,
  `Zip` int(11) DEFAULT NULL,
  `Email` varchar(100) DEFAULT NULL,
  `SDT` varchar(50) DEFAULT NULL,
  `TinhTrang` int(11) DEFAULT NULL,
  `MaTK` int(11) DEFAULT NULL,
  PRIMARY KEY (`makh`),
  UNIQUE KEY `unique_email` (`Email`),
  KEY `FK_KH_MATK_TK_idx` (`MaTK`),
  CONSTRAINT `FK_KH_MATK_TK` FOREIGN KEY (`MaTK`) REFERENCES `taikhoan` (`matk`) ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=1033 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `khachhang`
--

LOCK TABLES `khachhang` WRITE;
/*!40000 ALTER TABLE `khachhang` DISABLE KEYS */;
INSERT INTO `khachhang` VALUES (1010,'ongiaphu1','2000-06-15','Nam','Tra Vinh','HCM',23456789,'ongia@gmail.com','123456789',NULL,12),(1012,'zafuvip',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,14),(1013,'real',NULL,NULL,NULL,NULL,NULL,'okh1k59@gmail.com',NULL,NULL,15),(1015,'Nguyễn Công Phượng','2002-12-01','Nam','TPHCM','HCM',70000,'cf96@gmail.com','077211321201',NULL,17),(1016,'Thanh Sang',NULL,NULL,NULL,NULL,NULL,'sangpro123@gmail.com',NULL,NULL,18),(1017,'On Gia Phu','1998-08-12','Nam','123 Quang Trung','HCM',70000,'zafu1@gmail.com','0123456987',NULL,19),(1020,'Testing1',NULL,NULL,NULL,NULL,NULL,'tk1@gmail.com',NULL,NULL,22),(1024,'VVD',NULL,NULL,NULL,NULL,NULL,'vvd@ok.com',NULL,NULL,33),(1025,'hellobro',NULL,NULL,NULL,NULL,NULL,'iadjisdio@gmail.com',NULL,NULL,34),(1026,'Võ Văn Đức',NULL,NULL,NULL,NULL,NULL,'ducpro@gmail.com',NULL,NULL,35),(1027,'Võ Văn Đức','2022-11-02','Male','Da Oai','HCM',84,'voduc0100@gmail.com','0869990187',NULL,36),(1028,'Vo Van Duc','2002-11-02','Male','Da Oai, Da Huoai, Lam Dong','Lam Dong',12345,'duc89@gmail.com','0869990187',NULL,39),(1029,'Vo Van Duc',NULL,NULL,NULL,NULL,NULL,'duc91@gmail.com',NULL,NULL,40),(1030,'ajdasd',NULL,NULL,NULL,NULL,NULL,'aksdjn@aksjd',NULL,NULL,41),(1031,'Vo Van Duc',NULL,NULL,NULL,NULL,NULL,'duc93@gmail.com',NULL,NULL,42),(1032,'Vo Thi Tuyet Nhi',NULL,NULL,NULL,NULL,NULL,'nhi88@gmail.com',NULL,NULL,43);
/*!40000 ALTER TABLE `khachhang` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `lienhe`
--

DROP TABLE IF EXISTS `lienhe`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
 SET character_set_client = utf8mb4 ;
CREATE TABLE `lienhe` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `ten` varchar(50) CHARACTER SET utf8 COLLATE utf8_general_ci DEFAULT NULL,
  `email` varchar(50) CHARACTER SET utf8 COLLATE utf8_general_ci DEFAULT NULL,
  `chude` varchar(100) CHARACTER SET utf8 COLLATE utf8_general_ci DEFAULT NULL,
  `tinnhan` varchar(500) CHARACTER SET utf8 COLLATE utf8_general_ci DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=12 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `lienhe`
--

LOCK TABLES `lienhe` WRITE;
/*!40000 ALTER TABLE `lienhe` DISABLE KEYS */;
INSERT INTO `lienhe` VALUES (11,'Võ Văn Đức','20110635@student.hcmute.edu.vn','Login Error','I can\'t log in your web');
/*!40000 ALTER TABLE `lienhe` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `luong`
--

DROP TABLE IF EXISTS `luong`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
 SET character_set_client = utf8mb4 ;
CREATE TABLE `luong` (
  `maluong` int(11) NOT NULL AUTO_INCREMENT,
  `VaiTro` varchar(50) DEFAULT NULL,
  `HinhThuc` varchar(50) DEFAULT NULL,
  `LuongTheoGio` int(11) DEFAULT NULL,
  PRIMARY KEY (`maluong`)
) ENGINE=InnoDB AUTO_INCREMENT=100 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `luong`
--

LOCK TABLES `luong` WRITE;
/*!40000 ALTER TABLE `luong` DISABLE KEYS */;
INSERT INTO `luong` VALUES (1,'Nhan Vien','Part-time',50000),(2,'Admin','Full-time',80000);
/*!40000 ALTER TABLE `luong` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `nhanvien`
--


--
-- Table structure for table `giohang`
--

DROP TABLE IF EXISTS `giohang`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
 SET character_set_client = utf8mb4 ;
CREATE TABLE `giohang` (
  `MaGioHang` int(11) NOT NULL AUTO_INCREMENT,
  `MaKH` int(11) DEFAULT NULL,
  `ThoiGianTao` date DEFAULT NULL,
  `ThoiGianCapNhat` date DEFAULT NULL,
  `Tong` int(11) DEFAULT NULL,
  `TrangThai` tinyint(1) DEFAULT NULL,
  PRIMARY KEY (`MaGioHang`),
  KEY `FK_GH_MATK_TK_idx` (`MaKH`),
  CONSTRAINT `FK_GH_MATK_TK` FOREIGN KEY (`MaKH`) REFERENCES `khachhang` (`makh`) ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=30 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `giohang`
--

LOCK TABLES `giohang` WRITE;
/*!40000 ALTER TABLE `giohang` DISABLE KEYS */;
INSERT INTO `giohang` VALUES (24,1010,'2023-05-13','2023-05-14',NULL,1),(25,1025,'2023-05-13',NULL,NULL,1),(26,1026,'2023-05-25','2023-05-25',NULL,1),(28,1027,'2023-06-11','2023-06-12',NULL,1);
/*!40000 ALTER TABLE `giohang` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `giohang_chitiet`
--

DROP TABLE IF EXISTS `giohang_chitiet`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
 SET character_set_client = utf8mb4 ;
CREATE TABLE `giohang_chitiet` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `magiohang` int(11) DEFAULT NULL,
  `MaSP` int(11) DEFAULT NULL,
  `SoLuong` int(11) DEFAULT NULL,
  `GiaTien` int(11) DEFAULT NULL,
  `Tong` int(11) DEFAULT NULL,
  `ThoiGianMua` date DEFAULT NULL,
  `magiohangtam` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `FK_GHCT_ID_MGH_idx` (`magiohang`),
  KEY `FK_GHCT_MASP_SP_idx` (`MaSP`),
  KEY `FK_GHCT_MGHT_ID_idx` (`magiohangtam`),
  CONSTRAINT `FK_GHCT_ID_MGH` FOREIGN KEY (`magiohang`) REFERENCES `giohang` (`MaGioHang`) ON DELETE SET NULL ON UPDATE CASCADE,
  CONSTRAINT `FK_GHCT_MASP_SP` FOREIGN KEY (`MaSP`) REFERENCES `sanpham` (`masp`) ON DELETE SET NULL ON UPDATE CASCADE,
  CONSTRAINT `FK_GHCT_MGHT_ID` FOREIGN KEY (`magiohangtam`) REFERENCES `giohang_temp` (`id`) ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=219 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `giohang_chitiet`
--

LOCK TABLES `giohang_chitiet` WRITE;
/*!40000 ALTER TABLE `giohang_chitiet` DISABLE KEYS */;
INSERT INTO `giohang_chitiet` VALUES (1,NULL,6,1,80000,80000,NULL,NULL),(2,NULL,18,1,185000,185000,NULL,NULL),(3,NULL,21,2,170000,340000,NULL,NULL),(4,NULL,3,1,200000,200000,'2023-04-07',NULL),(14,NULL,18,1,185000,185000,'2023-04-07',NULL),(15,NULL,16,1,220000,220000,'2023-04-07',NULL),(16,NULL,18,1,185000,185000,'2023-04-07',NULL),(17,NULL,19,1,250000,250000,'2023-04-07',NULL),(26,NULL,18,1,185000,185000,'2023-04-07',4),(27,NULL,19,1,250000,250000,'2023-04-07',4),(28,NULL,21,4,170000,680000,'2023-04-07',5),(29,NULL,19,4,250000,1000000,'2023-04-07',5),(30,NULL,14,5,350000,1750000,'2023-04-07',6),(31,NULL,22,3,600000,1800000,'2023-04-07',6),(32,NULL,22,4,600000,2400000,'2023-04-07',7),(33,NULL,6,4,80000,320000,'2023-04-07',7),(34,NULL,19,4,250000,1000000,'2023-04-07',8),(35,NULL,17,3,310000,930000,'2023-04-07',8),(36,NULL,22,2,600000,1200000,'2023-04-07',9),(38,NULL,18,1,185000,185000,'2023-04-09',10),(39,NULL,18,1,185000,185000,'2023-04-09',NULL),(40,NULL,6,4,80000,320000,'2023-04-09',NULL),(41,NULL,22,5,600000,3000000,'2023-04-09',NULL),(42,NULL,21,2,170000,340000,'2023-04-09',NULL),(45,NULL,22,1,600000,600000,'2023-04-10',11),(77,NULL,18,3,185000,555000,'2023-04-11',NULL),(78,NULL,17,2,310000,620000,'2023-04-11',NULL),(79,NULL,22,2,600000,1200000,'2023-04-11',NULL),(80,NULL,13,1,750000,750000,'2023-04-11',NULL),(81,NULL,22,3,600000,1800000,'2023-04-11',NULL),(82,NULL,18,1,185000,185000,'2023-04-11',NULL),(83,NULL,18,1,185000,185000,'2023-04-12',23),(84,NULL,19,1,250000,250000,'2023-04-12',23),(85,NULL,18,2,185000,370000,'2023-04-12',24),(86,NULL,17,1,310000,310000,'2023-04-12',24),(87,NULL,18,1,185000,185000,'2023-04-12',25),(88,NULL,16,1,220000,220000,'2023-04-12',25),(89,NULL,6,1,80000,80000,'2023-04-12',26),(90,NULL,6,1,80000,80000,'2023-04-12',27),(91,NULL,14,1,350000,350000,'2023-04-12',28),(92,NULL,20,1,380000,380000,'2023-04-12',29),(93,NULL,18,1,185000,185000,'2023-04-12',30),(94,NULL,18,1,185000,185000,'2023-04-12',NULL),(95,NULL,18,1,185000,185000,'2023-04-12',31),(96,NULL,18,1,185000,185000,'2023-04-12',NULL),(97,NULL,22,2,600000,1200000,'2023-04-12',NULL),(98,NULL,6,2,80000,160000,'2023-04-12',NULL),(99,NULL,18,1,185000,185000,'2023-04-16',NULL),(100,NULL,21,1,170000,170000,'2023-04-16',NULL),(101,NULL,12,1,170000,170000,'2023-04-16',NULL),(102,NULL,16,1,220000,220000,'2023-04-16',NULL),(105,NULL,22,3,600000,1800000,'2023-04-16',NULL),(106,NULL,2,1,375000,375000,'2023-04-16',NULL),(107,NULL,18,2,185000,370000,'2023-04-17',NULL),(108,NULL,22,1,600000,600000,'2023-04-17',NULL),(109,NULL,21,3,170000,510000,'2023-04-17',NULL),(110,NULL,17,2,310000,620000,'2023-04-19',NULL),(111,NULL,18,1,185000,185000,'2023-04-19',NULL),(122,NULL,18,1,185000,185000,'2023-05-13',33),(128,NULL,18,1,185000,185000,'2023-05-13',34),(166,24,2,2,375000,750000,'2023-05-14',NULL),(167,26,6,1,50,50,'2023-05-25',NULL),(168,26,3,1,259,259,'2023-05-25',NULL),(169,NULL,15,1,100,100,'2023-06-10',35),(170,NULL,15,1,100,100,'2023-06-10',36),(171,NULL,15,1,100,100,'2023-06-10',37),(172,NULL,15,1,100,100,'2023-06-10',38),(173,NULL,15,1,100,100,'2023-06-10',39),(177,NULL,15,1,100,100,'2023-06-10',40),(178,NULL,15,1,100,100,'2023-06-10',40),(180,NULL,15,1,100,100,'2023-06-10',41),(181,NULL,15,1,100,100,'2023-06-10',41),(184,NULL,15,1,100,100,'2023-06-10',43),(186,NULL,15,4,100,400,'2023-06-10',45),(187,NULL,6,1,50,50,'2023-06-10',46),(188,NULL,21,1,55,55,'2023-06-10',47),(189,NULL,18,1,53,53,'2023-06-10',47),(193,NULL,6,1,50,50,'2023-06-10',48),(196,NULL,6,1,50,50,'2023-06-11',49),(197,NULL,6,1,50,50,'2023-06-11',50),(198,NULL,18,1,53,53,'2023-06-11',51),(199,NULL,18,1,53,53,'2023-06-11',52),(200,NULL,18,1,53,53,'2023-06-11',53),(201,NULL,18,1,53,53,'2023-06-11',54),(202,NULL,18,5,53,265,'2023-06-11',55),(204,NULL,18,3,53,159,'2023-06-11',56),(205,NULL,18,1,53,53,'2023-06-11',57),(206,NULL,21,3,55,165,'2023-06-11',58),(207,NULL,18,3,53,159,'2023-06-11',59),(208,NULL,18,3,53,159,'2023-06-11',60),(209,NULL,21,2,55,110,'2023-06-11',61),(214,28,19,4,21,84,'2023-06-12',NULL),(215,28,21,3,55,165,'2023-06-12',NULL);
/*!40000 ALTER TABLE `giohang_chitiet` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `giohang_temp`
--

DROP TABLE IF EXISTS `giohang_temp`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
 SET character_set_client = utf8mb4 ;
CREATE TABLE `giohang_temp` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `ThoiGianTao` date DEFAULT NULL,
  `ThoiGianCapNhat` date DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=62 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `giohang_temp`
--

LOCK TABLES `giohang_temp` WRITE;
/*!40000 ALTER TABLE `giohang_temp` DISABLE KEYS */;
INSERT INTO `giohang_temp` VALUES (1,'2023-04-07',NULL),(2,'2023-04-07',NULL),(3,'2023-04-07',NULL),(4,'2023-04-07',NULL),(5,'2023-04-07','2023-04-07'),(6,'2023-04-07','2023-04-07'),(7,'2023-04-07','2023-04-07'),(8,'2023-04-07','2023-04-07'),(9,'2023-04-07','2023-04-07'),(10,'2023-04-09','2023-04-09'),(11,'2023-04-10','2023-04-10'),(12,'2023-04-10','2023-04-10'),(13,'2023-04-10','2023-04-10'),(14,'2023-04-10','2023-04-10'),(15,'2023-04-10','2023-04-10'),(16,'2023-04-10','2023-04-10'),(17,'2023-04-10','2023-04-10'),(18,'2023-04-10','2023-04-10'),(19,'2023-04-10','2023-04-10'),(20,'2023-04-10','2023-04-10'),(21,'2023-04-10','2023-04-10'),(22,'2023-04-10','2023-04-10'),(23,'2023-04-12','2023-04-12'),(24,'2023-04-12','2023-04-12'),(25,'2023-04-12','2023-04-12'),(26,'2023-04-12','2023-04-12'),(27,'2023-04-12','2023-04-12'),(28,'2023-04-12','2023-04-12'),(29,'2023-04-12','2023-04-12'),(30,'2023-04-12','2023-04-12'),(31,'2023-04-12','2023-04-12'),(32,'2023-05-12','2023-05-12'),(33,'2023-05-13','2023-05-13'),(34,'2023-05-13','2023-05-13'),(35,'2023-06-10','2023-06-10'),(36,'2023-06-10','2023-06-10'),(37,'2023-06-10','2023-06-10'),(38,'2023-06-10','2023-06-10'),(39,'2023-06-10','2023-06-10'),(40,'2023-06-10','2023-06-10'),(41,'2023-06-10','2023-06-10'),(42,'2023-06-10','2023-06-10'),(43,'2023-06-10','2023-06-10'),(44,'2023-06-10','2023-06-10'),(45,'2023-06-10','2023-06-10'),(46,'2023-06-10','2023-06-10'),(47,'2023-06-10','2023-06-10'),(48,'2023-06-10','2023-06-10'),(49,'2023-06-11','2023-06-11'),(50,'2023-06-11','2023-06-11'),(51,'2023-06-11','2023-06-11'),(52,'2023-06-11','2023-06-11'),(53,'2023-06-11','2023-06-11'),(54,'2023-06-11','2023-06-11'),(55,'2023-06-11','2023-06-11'),(56,'2023-06-11','2023-06-11'),(57,'2023-06-11','2023-06-11'),(58,'2023-06-11','2023-06-11'),(59,'2023-06-11','2023-06-11'),(60,'2023-06-11','2023-06-11'),(61,'2023-06-11','2023-06-11');
/*!40000 ALTER TABLE `giohang_temp` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `hoadon`
--


--
-- Table structure for table `dathang`
--

DROP TABLE IF EXISTS `dathang`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
 SET character_set_client = utf8mb4 ;
CREATE TABLE `dathang` (
  `madathang` int(11) NOT NULL AUTO_INCREMENT,
  `MaKH` int(11) DEFAULT NULL,
  `NgayDatHang` date DEFAULT NULL,
  `SDT` varchar(45) DEFAULT NULL,
  `Email` varchar(100) DEFAULT NULL,
  `DiaChi` varchar(100) CHARACTER SET utf8 COLLATE utf8_general_ci DEFAULT NULL,
  `Tong` int(11) DEFAULT NULL,
  `TinhTrang` int(11) DEFAULT NULL,
  `PhuongThucThanhToan` int(11) DEFAULT NULL,
  `Zip` int(11) DEFAULT NULL,
  `ThanhPho` varchar(100) DEFAULT NULL,
  PRIMARY KEY (`madathang`),
  KEY `FK_DH_MAKH_KH_idx` (`MaKH`),
  KEY `FK_DH_PTTT_ID_idx` (`PhuongThucThanhToan`),
  CONSTRAINT `FK_DH_MAKH_KH` FOREIGN KEY (`MaKH`) REFERENCES `khachhang` (`makh`) ON DELETE SET NULL ON UPDATE CASCADE,
  CONSTRAINT `FK_DH_PTTT_ID` FOREIGN KEY (`PhuongThucThanhToan`) REFERENCES `phuongthuc_thanhtoan` (`id`) ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=58 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `dathang`
--

LOCK TABLES `dathang` WRITE;
/*!40000 ALTER TABLE `dathang` DISABLE KEYS */;
INSERT INTO `dathang` VALUES (8,1010,'2023-04-10','123456789','phu@gmail.com','ACDC/12',1380000,2,1,2580,'HN'),(10,1010,'2023-04-11','07721113120','phutv1990@gmail.com','TPHCM',1950000,2,1,4508,'HCM'),(11,1010,'2023-04-11','0789654123',NULL,'ACDC/12',1800000,2,1,2580,'HCM'),(13,1015,'2023-04-12','07721113120','cf96@gmail.com','TPHCM',185000,1,1,70000,'HCM'),(14,1016,'2023-04-12','0789654123','sangpro123@gmail.com','Quang Trung',1545000,1,1,70000,'HCM'),(16,1010,'2023-04-16','0789654123','phu123@gmail.com','',2175000,4,1,2580,'HCM'),(18,1015,'2023-04-17','07721132120','cf96@gmail.com','',510000,4,1,70000,'HCM'),(19,1010,'2023-04-19','01472583690','phutv1990@gmail.com','TPHCM',805000,4,1,70000,'HCM'),(22,1020,'2023-04-22','0789654123','tk1@gmail.com','Lê Thánh Tôn',405000,1,1,4508,'HCM'),(23,1010,'2023-05-14','345678','tyhuj@mgi.com','Chau Thoi',0,1,2,23434654,'Binh Duong'),(24,1010,'2023-05-14','34234234','Phu@gmail.com','asjdjsa',375000,1,1,1242343,'Been Hoa'),(25,1010,'2023-05-14','345678','tyhuj@mgi.com','Chau Thoi',0,1,2,23434654,'Binh Duong'),(26,1010,'2023-05-14','345678','tyhuj@mgi.com','Chau Thoi',0,1,2,23434654,'Binh Duong'),(27,1010,'2023-05-14','234324234','adasdsad','dasdas',1125000,1,1,24324324,'asdasd'),(28,1010,'2023-05-14','12321434','sdassdas\n','adasdsad',200000,1,1,213324345,'asdasd'),(29,1010,'2023-05-14','3243243','adasd','asdasdsad',750000,1,1,123,'sddad'),(30,1010,'2023-05-14','2423424','asdasd','asdasdxzce',400000,1,1,34234,'asdasd'),(31,1010,'2023-05-14','4234324','asdasd','weqweqw',950000,1,1,22423432,'sadasd'),(32,1010,'2023-05-14','34324234','sadsad','asdsad',600000,1,2,23434,'sdasd'),(33,1010,'2023-05-14','3234','asdasd','asdasd',400000,1,1,34324,'sadasd'),(34,1010,'2023-05-14','45435','asdasd','qweqwewq',400000,1,1,34234234,'dadsad'),(35,1010,'2023-05-14','34234','adasdsda','asdad',375000,1,1,34234,'adasd'),(36,1010,'2023-05-14','124534545','fsfdfdfsd','123123123',800000,1,1,124214214,'12312321'),(37,1010,'2023-05-14','234243','adsad','asdasd',600000,1,2,1232423,'asdasd'),(38,1010,'2023-05-14','434','asdasd','asdasd',375000,1,1,123123,'asdasd'),(39,1010,'2023-05-14','235235','dsadasd','qweqweqwe',3150000,1,1,1234324,'asdasd'),(40,1027,'2023-06-11','0913605573','20110635@student.hcmute.edu.vn','Ký túc xá khu B, đại học quốc gia, thành phố HCM',318,3,1,65535,'Bình Dương'),(41,1027,'2023-06-11','0913605573','20110635@student.hcmute.edu.vn','Ký túc xá khu B, đại học quốc gia, thành phố HCM',368,1,1,4654,'Bình Dương'),(42,1027,'2023-06-12','0913605573','voduc0100@gmail.com','Ký túc xá khu B, đại học quốc gia, thành phố HCM',305,1,1,53132,'Bình Dương'),(43,1027,'2023-06-12','0913605573','voduc0100@gmail.com','Ký túc xá khu B, đại học quốc gia, thành phố HCM',305,1,1,53132,'Bình Dương'),(44,1027,'2023-06-12','0913605573','voduc0100@gmail.com','Ký túc xá khu B, đại học quốc gia, thành phố HCM',305,1,1,4422,'Bình Dương'),(45,1027,'2023-06-12','0913605573','voduc0100@gmail.com','Ký túc xá khu B, đại học quốc gia, thành phố HCM',305,1,1,5641,'Bình Dương'),(46,1027,'2023-06-12','0913605573','20110635@student.hcmute.edu.vn','Ký túc xá khu B, đại học quốc gia, thành phố HCM',284,1,1,5,'Bình Dương'),(47,1027,'2023-06-12','0913605573','20110635@student.hcmute.edu.vn','Ký túc xá khu B, đại học quốc gia, thành phố HCM',284,1,1,52,'Bình Dương'),(48,1027,'2023-06-12','0913605573','20110635@student.hcmute.edu.vn','Ký túc xá khu B, đại học quốc gia, thành phố HCM',284,1,1,5257,'Bình Dương'),(49,1027,'2023-06-12','0913605573','20110635@student.hcmute.edu.vn','Ký túc xá khu B, đại học quốc gia, thành phố HCM',326,1,1,6453,'Bình Dương'),(50,1027,'2023-06-12','0913605573','voduc0100@gmail.com','Ký túc xá khu B, đại học quốc gia, thành phố HCM',263,1,1,15313,'Bình Dương'),(51,1027,'2023-06-12','0913605573','20110635@student.hcmute.edu.vn','Ký túc xá khu B, đại học quốc gia, thành phố HCM',242,4,1,4864,'Bình Dương'),(52,1027,'2023-06-12','0913605573','20110635@student.hcmute.edu.vn','Ký túc xá khu B, đại học quốc gia, thành phố HCM',384,1,1,1156,'Bình Dương'),(53,1027,'2023-06-12','0913605573','20110635@student.hcmute.edu.vn','Ký túc xá khu B, đại học quốc gia, thành phố HCM',426,3,1,561,'Bình Dương'),(54,1027,'2023-06-12','0913605573','20110635@student.hcmute.edu.vn','Ký túc xá khu B, đại học quốc gia, thành phố HCM',384,3,1,152,'Bình Dương'),(55,1027,'2023-06-12','0913605573','20110635@student.hcmute.edu.vn','Ký túc xá khu B, đại học quốc gia, thành phố HCM',249,3,1,542,'Bình Dương'),(56,1027,'2023-06-12','0913605573','20110635@student.hcmute.edu.vn','Ký túc xá khu B, đại học quốc gia, thành phố HCM',249,1,1,155,'Bình Dương'),(57,1028,'2023-06-17','0869990187','duc89@gmail.com','',413,4,1,1,'');
/*!40000 ALTER TABLE `dathang` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `dathang_chitiet`
--

DROP TABLE IF EXISTS `dathang_chitiet`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
 SET character_set_client = utf8mb4 ;
CREATE TABLE `dathang_chitiet` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `MaDatHang` int(11) DEFAULT NULL,
  `MaSP` int(11) DEFAULT NULL,
  `SoLuong` int(11) DEFAULT NULL,
  `GiaTien` int(11) DEFAULT NULL,
  `Tong` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `FK_DHCT_MADH_DH_idx` (`MaDatHang`),
  KEY `FK_DHCT_MASP_SP_idx` (`MaSP`),
  CONSTRAINT `FK_DHCT_MADH_DH` FOREIGN KEY (`MaDatHang`) REFERENCES `dathang` (`madathang`) ON DELETE SET NULL ON UPDATE CASCADE,
  CONSTRAINT `FK_DHCT_MASP_SP` FOREIGN KEY (`MaSP`) REFERENCES `sanpham` (`masp`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=104 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `dathang_chitiet`
--

LOCK TABLES `dathang_chitiet` WRITE;
/*!40000 ALTER TABLE `dathang_chitiet` DISABLE KEYS */;
INSERT INTO `dathang_chitiet` VALUES (1,NULL,18,5,185000,NULL),(2,NULL,18,5,185000,NULL),(3,NULL,18,5,185000,925000),(4,NULL,6,4,80000,320000),(5,NULL,22,5,600000,3000000),(6,NULL,18,5,185000,925000),(7,NULL,6,4,80000,320000),(8,NULL,22,5,600000,3000000),(9,NULL,18,5,185000,925000),(10,NULL,6,4,80000,320000),(11,NULL,22,5,600000,3000000),(12,NULL,18,5,185000,925000),(13,NULL,6,4,80000,320000),(14,NULL,22,5,600000,3000000),(15,NULL,18,1,185000,185000),(16,NULL,6,4,80000,320000),(17,NULL,22,5,600000,3000000),(18,NULL,21,2,170000,340000),(19,8,21,2,170000,340000),(20,8,3,1,200000,200000),(21,8,18,1,185000,185000),(22,8,16,1,220000,220000),(23,8,18,1,185000,185000),(24,8,19,1,250000,250000),(27,10,22,2,600000,1200000),(28,10,13,1,750000,750000),(29,11,22,3,600000,1800000),(31,13,18,1,185000,185000),(32,14,18,1,185000,185000),(33,14,22,2,600000,1200000),(34,14,6,2,80000,160000),(36,16,22,3,600000,1800000),(37,16,2,1,375000,375000),(40,18,21,3,170000,510000),(41,19,17,2,310000,620000),(42,19,18,1,185000,185000),(46,22,18,1,185000,185000),(47,22,16,1,220000,220000),(48,24,2,1,375000,375000),(49,27,2,3,375000,1125000),(50,28,3,1,200000,200000),(51,29,2,2,375000,750000),(52,30,3,2,200000,400000),(53,31,1,1,950000,950000),(54,32,3,3,200000,600000),(55,33,3,2,200000,400000),(56,34,3,2,200000,400000),(57,35,2,1,375000,375000),(58,36,3,4,200000,800000),(59,37,3,3,200000,600000),(60,38,2,1,375000,375000),(61,39,3,5,200000,1000000),(62,39,4,4,300000,1200000),(63,39,1,1,950000,950000),(64,40,21,1,55,55),(65,40,18,1,53,53),(66,40,6,1,50,50),(67,40,6,1,50,50),(68,40,21,2,55,110),(69,41,22,2,100,200),(70,41,19,8,23,168),(71,42,22,2,100,200),(72,42,19,5,23,105),(73,43,22,2,100,200),(74,43,19,5,23,105),(75,44,22,2,100,200),(76,44,19,5,23,105),(77,45,22,2,100,200),(78,45,19,5,23,105),(79,46,22,2,100,200),(80,46,19,4,23,84),(81,47,22,2,100,200),(82,47,19,4,23,84),(83,48,22,2,100,200),(84,48,19,4,23,84),(85,49,22,2,100,200),(86,49,19,6,23,126),(87,50,22,2,100,200),(88,50,19,3,21,63),(89,51,22,2,100,200),(90,51,19,2,21,42),(91,52,22,3,100,300),(92,52,19,4,21,84),(93,53,22,3,100,300),(94,53,19,6,21,126),(95,54,22,3,100,300),(96,54,19,4,21,84),(97,55,19,4,21,84),(98,55,21,3,55,165),(99,56,19,4,21,84),(100,56,21,3,55,165),(101,57,6,1,50,50),(102,57,22,3,100,300),(103,57,19,3,21,63);
/*!40000 ALTER TABLE `dathang_chitiet` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `donhangdagiaouser`
--

DROP TABLE IF EXISTS `donhangdagiaouser`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
 SET character_set_client = utf8mb4 ;
CREATE TABLE `donhangdagiaouser` (
  `userId` int(11) NOT NULL,
  `orderID` int(11) DEFAULT NULL,
  `trangthai` int(11) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `donhangdagiaouser`
--

LOCK TABLES `donhangdagiaouser` WRITE;
/*!40000 ALTER TABLE `donhangdagiaouser` DISABLE KEYS */;
/*!40000 ALTER TABLE `donhangdagiaouser` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `emailcode`
--

DROP TABLE IF EXISTS `emailcode`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
 SET character_set_client = utf8mb4 ;
CREATE TABLE `emailcode` (
  `email` varchar(50) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL,
  `maxacthuc` varchar(50) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci DEFAULT NULL,
  PRIMARY KEY (`email`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `emailcode`
--

LOCK TABLES `emailcode` WRITE;
/*!40000 ALTER TABLE `emailcode` DISABLE KEYS */;
/*!40000 ALTER TABLE `emailcode` ENABLE KEYS */;
UNLOCK TABLES;


DROP TABLE IF EXISTS `hoadon`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
 SET character_set_client = utf8mb4 ;
CREATE TABLE `hoadon` (
  `mahoadon` int(11) NOT NULL AUTO_INCREMENT,
  `MaKH` int(11) DEFAULT NULL,
  `NgayMua` date DEFAULT NULL,
  `Tong` int(11) DEFAULT NULL,
  PRIMARY KEY (`mahoadon`),
  KEY `FK_HD_MKH_KH` (`MaKH`),
  CONSTRAINT `FK_HD_MKH_KH` FOREIGN KEY (`MaKH`) REFERENCES `khachhang` (`makh`) ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=1020 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `hoadon`
--

LOCK TABLES `hoadon` WRITE;
/*!40000 ALTER TABLE `hoadon` DISABLE KEYS */;
INSERT INTO `hoadon` VALUES (1000,1015,'2023-04-12',185000),(1001,1016,'2023-04-12',1545000),(1002,1010,'2023-04-10',1380000),(1004,1010,'2023-04-16',2175000),(1005,1010,'2023-04-16',2175000),(1006,1010,'2023-04-10',1380000),(1007,1010,'2023-04-11',1950000),(1008,1010,'2023-04-11',1800000),(1010,1015,'2023-04-17',510000),(1011,1015,'2023-04-17',510000),(1012,1010,'2023-04-16',2175000),(1013,1010,'2023-04-19',805000),(1014,1027,'2023-06-12',242),(1015,1027,'2023-06-12',426),(1016,1027,'2023-06-12',384),(1017,1027,'2023-06-12',273),(1018,1027,'2023-06-11',349),(1019,1028,'2023-06-17',454);
/*!40000 ALTER TABLE `hoadon` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `hoadon_chitiet`
--

DROP TABLE IF EXISTS `hoadon_chitiet`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
 SET character_set_client = utf8mb4 ;
CREATE TABLE `hoadon_chitiet` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `MaHoaDon` int(11) DEFAULT NULL,
  `MaSP` int(11) DEFAULT NULL,
  `SoLuong` int(11) DEFAULT NULL,
  `GiaTien` int(11) DEFAULT NULL,
  `Tong` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `FK_HDCT_MSP_SP_idx` (`MaSP`),
  KEY `FK_HDCT_MHD_HD_idx` (`MaHoaDon`),
  CONSTRAINT `FK_HDCT_MASP_SP` FOREIGN KEY (`MaSP`) REFERENCES `sanpham` (`masp`) ON DELETE SET NULL ON UPDATE CASCADE,
  CONSTRAINT `FK_HDCT_MHD_HD` FOREIGN KEY (`MaHoaDon`) REFERENCES `hoadon` (`mahoadon`) ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=49 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `hoadon_chitiet`
--

LOCK TABLES `hoadon_chitiet` WRITE;
/*!40000 ALTER TABLE `hoadon_chitiet` DISABLE KEYS */;
INSERT INTO `hoadon_chitiet` VALUES (1,1000,18,1,185000,185000),(2,1001,18,1,185000,185000),(3,1001,22,2,600000,1200000),(4,1001,6,2,80000,160000),(5,1002,21,2,170000,340000),(6,1002,3,1,200000,200000),(7,1002,18,1,185000,185000),(8,1002,16,1,220000,220000),(9,1002,18,1,185000,185000),(10,1002,19,1,250000,250000),(12,1004,22,3,600000,1800000),(13,1004,2,1,375000,375000),(14,1005,22,3,600000,1800000),(15,1005,2,1,375000,375000),(16,1006,21,2,170000,340000),(17,1006,3,1,200000,200000),(18,1006,18,1,185000,185000),(19,1006,16,1,220000,220000),(20,1006,18,1,185000,185000),(21,1006,19,1,250000,250000),(22,1007,22,2,600000,1200000),(23,1007,13,1,750000,750000),(24,1008,22,3,600000,1800000),(27,1010,21,3,170000,510000),(28,1011,21,3,170000,510000),(29,1012,22,3,600000,1800000),(30,1012,2,1,375000,375000),(31,1013,17,2,310000,620000),(32,1013,18,1,185000,185000),(33,1014,22,2,100,200),(34,1014,19,2,21,42),(35,1015,22,3,100,300),(36,1015,19,6,21,126),(37,1016,22,3,100,300),(38,1016,19,4,21,84),(39,1017,19,4,21,84),(40,1017,21,3,55,165),(41,1018,21,1,55,55),(42,1018,18,1,53,53),(43,1018,6,1,50,50),(44,1018,6,1,50,50),(45,1018,21,2,55,110),(46,1019,6,1,50,50),(47,1019,22,3,100,300),(48,1019,19,3,21,63);
/*!40000 ALTER TABLE `hoadon_chitiet` ENABLE KEYS */;
UNLOCK TABLES;


DROP TABLE IF EXISTS `nhanvien`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
 SET character_set_client = utf8mb4 ;
CREATE TABLE `nhanvien` (
  `manv` int(11) NOT NULL AUTO_INCREMENT,
  `HoTen` varchar(50) DEFAULT NULL,
  `NgaySinh` date DEFAULT NULL,
  `GioiTinh` varchar(50) NOT NULL,
  `SDT` varchar(50) DEFAULT NULL,
  `MaLuong` int(11) DEFAULT NULL,
  `MaTK` int(11) DEFAULT NULL,
  `TinhTrang` int(11) DEFAULT NULL,
  PRIMARY KEY (`manv`),
  UNIQUE KEY `UQ__NhanVien__CA1930A552DDABDA` (`SDT`),
  KEY `FK_NHANVIEN_MATK_TK_idx` (`MaTK`),
  KEY `FK_NHANVIEN_ML_LUONG_idx` (`MaLuong`),
  CONSTRAINT `FK_NHANVIEN_MATK_TK` FOREIGN KEY (`MaTK`) REFERENCES `taikhoan` (`matk`) ON DELETE SET NULL ON UPDATE CASCADE,
  CONSTRAINT `FK_NHANVIEN_ML_LUONG` FOREIGN KEY (`MaLuong`) REFERENCES `luong` (`maluong`) ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=13 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `nhanvien`
--

LOCK TABLES `nhanvien` WRITE;
/*!40000 ALTER TABLE `nhanvien` DISABLE KEYS */;
INSERT INTO `nhanvien` VALUES (1,'Huynh Banh','1996-10-10','Nam','0123456789',1,31,0),(2,'Nguyen An','1998-06-12','Nu','0987654321',1,23,1),(3,'Tran Bich Thuy','2000-01-11','Nu','0111111111',2,28,1),(4,'Tran Canh','1997-07-26','Nam','0147258369',2,29,1),(11,'Nguyễn Công Phượng','1998-08-17','Nam','07721132120',NULL,32,1),(12,'Vo Van','2002-12-01','Male','0869990187',NULL,37,0);
/*!40000 ALTER TABLE `nhanvien` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `phanhoi`
--

DROP TABLE IF EXISTS `phanhoi`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
 SET character_set_client = utf8mb4 ;
CREATE TABLE `phanhoi` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `masp` int(11) NOT NULL,
  `makh` int(11) NOT NULL,
  `noidung` varchar(500) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci DEFAULT NULL,
  `ngayph` date DEFAULT NULL,
  `sosao` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `FK_PHANHOI_MASP_SP_idx` (`masp`),
  KEY `FK_PHANHOI_MAKH_KH_idx` (`makh`),
  CONSTRAINT `FK_PHANHOI_MAKH_KH` FOREIGN KEY (`makh`) REFERENCES `khachhang` (`makh`) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT `FK_PHANHOI_MASP_SP` FOREIGN KEY (`masp`) REFERENCES `sanpham` (`masp`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=115 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `phanhoi`
--

LOCK TABLES `phanhoi` WRITE;
/*!40000 ALTER TABLE `phanhoi` DISABLE KEYS */;
INSERT INTO `phanhoi` VALUES (101,11,1010,'ok','2023-05-13',5),(102,11,1010,'\"ngon\"','2023-05-14',4),(103,11,1010,'haha','2023-05-14',5),(104,3,1010,'hahahaa','2023-05-14',3),(105,3,1010,'chao` thay`','2023-05-14',5),(106,15,1010,'ngon1','2023-06-11',4),(107,15,1010,'ngon2','2023-06-11',3),(108,15,1010,'ngon3','2023-06-11',5),(109,15,1027,'giày này đẹp đấy bro!','2023-06-11',4),(110,15,1027,'','2023-06-11',5),(111,15,1027,'hihi',NULL,3),(112,18,1028,'That\'s amazing',NULL,4),(114,18,1028,'hihi',NULL,3);
/*!40000 ALTER TABLE `phanhoi` ENABLE KEYS */;
UNLOCK TABLES;


/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2023-06-18 10:46:44
