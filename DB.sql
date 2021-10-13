-- MySQL Script generated by MySQL Workbench
-- Tue Oct 12 23:02:31 2021
-- Model: New Model    Version: 1.0
-- MySQL Workbench Forward Engineering

SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0;
SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0;
SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='ONLY_FULL_GROUP_BY,STRICT_TRANS_TABLES,NO_ZERO_IN_DATE,NO_ZERO_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION';

-- -----------------------------------------------------
-- Schema mydb
-- -----------------------------------------------------
-- -----------------------------------------------------
-- Schema tutaller
-- -----------------------------------------------------

-- -----------------------------------------------------
-- Schema tutaller
-- -----------------------------------------------------
CREATE SCHEMA IF NOT EXISTS `tutaller` DEFAULT CHARACTER SET utf8 ;
USE `tutaller` ;

-- -----------------------------------------------------
-- Table `tutaller`.`country`
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS `tutaller`.`country` (
  `id` TINYINT(4) NOT NULL AUTO_INCREMENT,
  `country_name` VARCHAR(56) NOT NULL,
  PRIMARY KEY (`id`))
ENGINE = InnoDB
AUTO_INCREMENT = 2
DEFAULT CHARACTER SET = utf8;


-- -----------------------------------------------------
-- Table `tutaller`.`region`
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS `tutaller`.`region` (
  `id` SMALLINT(6) NOT NULL,
  `country_id` TINYINT(4) NOT NULL,
  `region_name` VARCHAR(60) NOT NULL,
  PRIMARY KEY (`id`),
  CONSTRAINT `fk_region_country1`
    FOREIGN KEY (`country_id`)
    REFERENCES `tutaller`.`country` (`id`)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION)
ENGINE = InnoDB
DEFAULT CHARACTER SET = utf8;


-- -----------------------------------------------------
-- Table `tutaller`.`commune`
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS `tutaller`.`commune` (
  `id` SMALLINT(6) NOT NULL AUTO_INCREMENT,
  `region_id` SMALLINT(6) NOT NULL,
  `commune_name` VARCHAR(60) NOT NULL,
  PRIMARY KEY (`id`),
  CONSTRAINT `fk_commune_region1`
    FOREIGN KEY (`region_id`)
    REFERENCES `tutaller`.`region` (`id`)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION)
ENGINE = InnoDB
AUTO_INCREMENT = 2
DEFAULT CHARACTER SET = utf8;


-- -----------------------------------------------------
-- Table `tutaller`.`email_validate_codes`
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS `tutaller`.`email_validate_codes` (
  `id` INT(11) NOT NULL AUTO_INCREMENT,
  `user_email` VARCHAR(45) NOT NULL,
  `recovery_code` INT(5) NOT NULL,
  PRIMARY KEY (`id`))
ENGINE = InnoDB
AUTO_INCREMENT = 17
DEFAULT CHARACTER SET = utf8;


-- -----------------------------------------------------
-- Table `tutaller`.`image`
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS `tutaller`.`image` (
  `id` INT(11) NOT NULL AUTO_INCREMENT,
  `image_name` VARCHAR(45) NOT NULL,
  `image_path` VARCHAR(200) NOT NULL,
  `image_ext` VARCHAR(15) NOT NULL,
  PRIMARY KEY (`id`))
ENGINE = InnoDB
DEFAULT CHARACTER SET = utf8;


-- -----------------------------------------------------
-- Table `tutaller`.`offer`
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS `tutaller`.`offer` (
  `id` INT(11) NOT NULL AUTO_INCREMENT,
  `offer_name` VARCHAR(45) NOT NULL,
  `offer_discount` TINYINT(100) NOT NULL,
  PRIMARY KEY (`id`))
ENGINE = InnoDB
AUTO_INCREMENT = 2
DEFAULT CHARACTER SET = utf8;


-- -----------------------------------------------------
-- Table `tutaller`.`user_type`
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS `tutaller`.`user_type` (
  `id` INT(11) NOT NULL AUTO_INCREMENT,
  `user_type_name` VARCHAR(45) NOT NULL,
  `user_type_description` VARCHAR(45) NOT NULL,
  PRIMARY KEY (`id`))
ENGINE = InnoDB
AUTO_INCREMENT = 5
DEFAULT CHARACTER SET = utf8;


-- -----------------------------------------------------
-- Table `tutaller`.`user`
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS `tutaller`.`user` (
  `user_rut` INT(11) NOT NULL,
  `user_type_id` INT(11) NOT NULL,
  `user_name` VARCHAR(45) NOT NULL,
  `user_last_name` VARCHAR(45) NOT NULL,
  `user_email` VARCHAR(45) NOT NULL,
  `user_phone` INT(11) NOT NULL,
  `user_password` VARCHAR(65) NOT NULL,
  `user_status` VARCHAR(45) NOT NULL,
  PRIMARY KEY (`user_rut`),
  UNIQUE INDEX `user_email_UNIQUE` (`user_email` ASC),
  UNIQUE INDEX `user_phone_UNIQUE` (`user_phone` ASC),
  CONSTRAINT `fk_user_user_type1`
    FOREIGN KEY (`user_type_id`)
    REFERENCES `tutaller`.`user_type` (`id`)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION)
ENGINE = InnoDB
DEFAULT CHARACTER SET = utf8;


-- -----------------------------------------------------
-- Table `tutaller`.`workshop`
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS `tutaller`.`workshop` (
  `id` SMALLINT(6) NOT NULL AUTO_INCREMENT,
  `workshop_name` VARCHAR(45) NOT NULL,
  `workshop_number` INT(11) NOT NULL,
  `workshop_description` VARCHAR(580) NOT NULL,
  PRIMARY KEY (`id`))
ENGINE = InnoDB
AUTO_INCREMENT = 37
DEFAULT CHARACTER SET = utf8;


-- -----------------------------------------------------
-- Table `tutaller`.`workshop_suscription`
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS `tutaller`.`workshop_suscription` (
  `id` INT(11) NOT NULL AUTO_INCREMENT,
  `offer_id` INT(11) NOT NULL,
  `name` VARCHAR(45) NOT NULL,
  `price` INT(11) NOT NULL,
  `description` VARCHAR(99) NOT NULL,
  PRIMARY KEY (`id`),
  CONSTRAINT `fk_workshop_suscription_offer1`
    FOREIGN KEY (`offer_id`)
    REFERENCES `tutaller`.`offer` (`id`)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION)
ENGINE = InnoDB
AUTO_INCREMENT = 2
DEFAULT CHARACTER SET = utf8;


-- -----------------------------------------------------
-- Table `tutaller`.`workshop_office`
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS `tutaller`.`workshop_office` (
  `id` SMALLINT(6) NOT NULL AUTO_INCREMENT,
  `workshop_id` SMALLINT(6) NOT NULL,
  `commune_id` SMALLINT(6) NOT NULL,
  `workshop_suscription_id` INT(11) NOT NULL,
  `workshop_office_address` VARCHAR(45) NOT NULL,
  `workshop_office_phone` INT(11) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE INDEX `workshop_office_address_UNIQUE` (`workshop_office_address` ASC),
  CONSTRAINT `fk_workshop_office_commune1`
    FOREIGN KEY (`commune_id`)
    REFERENCES `tutaller`.`commune` (`id`)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION,
  CONSTRAINT `fk_workshop_office_workshop1`
    FOREIGN KEY (`workshop_id`)
    REFERENCES `tutaller`.`workshop` (`id`)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION,
  CONSTRAINT `fk_workshop_office_workshop_suscription1`
    FOREIGN KEY (`workshop_suscription_id`)
    REFERENCES `tutaller`.`workshop_suscription` (`id`)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION)
ENGINE = InnoDB
AUTO_INCREMENT = 31
DEFAULT CHARACTER SET = utf8;


-- -----------------------------------------------------
-- Table `tutaller`.`workshop_office_employee`
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS `tutaller`.`workshop_office_employee` (
  `id` INT(11) NOT NULL AUTO_INCREMENT,
  `workshop_office_id` SMALLINT(6) NOT NULL,
  `user_rut` INT(11) NOT NULL,
  `workshop_office_employee_specialization` VARCHAR(45) NOT NULL,
  `workshop_office_employee_experience` VARCHAR(45) NOT NULL,
  PRIMARY KEY (`id`),
  CONSTRAINT `fk_employee_user1`
    FOREIGN KEY (`user_rut`)
    REFERENCES `tutaller`.`user` (`user_rut`)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION,
  CONSTRAINT `fk_employee_workshop_office1`
    FOREIGN KEY (`workshop_office_id`)
    REFERENCES `tutaller`.`workshop_office` (`id`)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION)
ENGINE = InnoDB
DEFAULT CHARACTER SET = utf8;


-- -----------------------------------------------------
-- Table `tutaller`.`workshop_office_service`
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS `tutaller`.`workshop_office_service` (
  `id` INT(11) NOT NULL AUTO_INCREMENT,
  `workshop_office_id` SMALLINT(6) NOT NULL,
  `offer_id` INT(11) NOT NULL,
  `workshop_office_service_name` VARCHAR(45) NOT NULL,
  `workshop_office_service_price` INT(11) NOT NULL,
  `workshop_office_service_estimated_time` INT(11) NOT NULL,
  `workshop_office_service_description` VARCHAR(99) NOT NULL,
  PRIMARY KEY (`id`),
  CONSTRAINT `fk_workshop_office_service_offer1`
    FOREIGN KEY (`offer_id`)
    REFERENCES `tutaller`.`offer` (`id`)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION,
  CONSTRAINT `fk_workshop_office_service_workshop_office1`
    FOREIGN KEY (`workshop_office_id`)
    REFERENCES `tutaller`.`workshop_office` (`id`)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION)
ENGINE = InnoDB
DEFAULT CHARACTER SET = utf8;


-- -----------------------------------------------------
-- Table `tutaller`.`workshop_office_work`
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS `tutaller`.`workshop_office_work` (
  `id` INT(11) NOT NULL AUTO_INCREMENT,
  `workshop_office_service_id` INT(11) NOT NULL,
  `employee_id` INT(11) NOT NULL,
  `user_user_rut` INT(11) NOT NULL,
  `workshop_office_work_status` VARCHAR(45) NOT NULL,
  PRIMARY KEY (`id`),
  CONSTRAINT `fk_workshop_office_work_employee1`
    FOREIGN KEY (`employee_id`)
    REFERENCES `tutaller`.`workshop_office_employee` (`id`)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION,
  CONSTRAINT `fk_workshop_office_work_user1`
    FOREIGN KEY (`user_user_rut`)
    REFERENCES `tutaller`.`user` (`user_rut`)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION,
  CONSTRAINT `fk_workshop_office_work_workshop_office_service1`
    FOREIGN KEY (`workshop_office_service_id`)
    REFERENCES `tutaller`.`workshop_office_service` (`id`)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION)
ENGINE = InnoDB
DEFAULT CHARACTER SET = utf8;


-- -----------------------------------------------------
-- Table `tutaller`.`office_work_technical_report`
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS `tutaller`.`office_work_technical_report` (
  `id` INT(11) NOT NULL AUTO_INCREMENT,
  `workshop_office_work_id` INT(11) NOT NULL,
  `office_work_technical_report_km` INT(11) NOT NULL,
  `office_work_technical_report_ppu` VARCHAR(10) NOT NULL,
  `office_work_technical_report_fuel_type` VARCHAR(45) NOT NULL,
  `office_work_technical_report_color` VARCHAR(45) NOT NULL,
  `office_work_technical_report_engine` VARCHAR(45) NOT NULL,
  `office_work_technical_report_model` VARCHAR(45) NOT NULL,
  `office_work_technical_report_brand` VARCHAR(45) NOT NULL,
  `office_work_technical_report_chassis` VARCHAR(45) NOT NULL,
  `office_work_technical_report_description` VARCHAR(580) NOT NULL,
  PRIMARY KEY (`id`),
  CONSTRAINT `fk_office_work_technical_report_workshop_office_work1`
    FOREIGN KEY (`workshop_office_work_id`)
    REFERENCES `tutaller`.`workshop_office_work` (`id`)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION)
ENGINE = InnoDB
DEFAULT CHARACTER SET = utf8;


-- -----------------------------------------------------
-- Table `tutaller`.`password_reset_codes`
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS `tutaller`.`password_reset_codes` (
  `id` INT(11) NOT NULL AUTO_INCREMENT,
  `user_email` VARCHAR(45) NOT NULL,
  `recovery_code` INT(5) NOT NULL,
  PRIMARY KEY (`id`))
ENGINE = InnoDB
AUTO_INCREMENT = 67
DEFAULT CHARACTER SET = utf8;


-- -----------------------------------------------------
-- Table `tutaller`.`payment_method`
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS `tutaller`.`payment_method` (
  `id` INT(11) NOT NULL AUTO_INCREMENT,
  `payment_method_name` VARCHAR(45) NOT NULL,
  PRIMARY KEY (`id`))
ENGINE = InnoDB
DEFAULT CHARACTER SET = utf8;


-- -----------------------------------------------------
-- Table `tutaller`.`payment_receipt`
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS `tutaller`.`payment_receipt` (
  `id` INT(11) NOT NULL AUTO_INCREMENT,
  `user_rut` INT(11) NOT NULL,
  `payment_receipt_date` DATE NOT NULL,
  `payment_receipt_time` TIME NOT NULL,
  PRIMARY KEY (`id`),
  CONSTRAINT `fk_payment_receipt_user1`
    FOREIGN KEY (`user_rut`)
    REFERENCES `tutaller`.`user` (`user_rut`)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION)
ENGINE = InnoDB
DEFAULT CHARACTER SET = utf8;


-- -----------------------------------------------------
-- Table `tutaller`.`payment_receipt_method`
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS `tutaller`.`payment_receipt_method` (
  `id` INT(11) NOT NULL AUTO_INCREMENT,
  `payment_receipt_id` INT(11) NOT NULL,
  `payment_method_id` INT(11) NOT NULL,
  PRIMARY KEY (`id`),
  CONSTRAINT `fk_payment_receipt_method_payment_method1`
    FOREIGN KEY (`payment_method_id`)
    REFERENCES `tutaller`.`payment_method` (`id`)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION,
  CONSTRAINT `fk_payment_receipt_method_payment_receipt1`
    FOREIGN KEY (`payment_receipt_id`)
    REFERENCES `tutaller`.`payment_receipt` (`id`)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION)
ENGINE = InnoDB
DEFAULT CHARACTER SET = utf8;


-- -----------------------------------------------------
-- Table `tutaller`.`payment_receipt_suscription`
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS `tutaller`.`payment_receipt_suscription` (
  `id` INT(11) NOT NULL AUTO_INCREMENT,
  `workshop_suscription_id` INT(11) NOT NULL,
  `payment_receipt_id` INT(11) NOT NULL,
  PRIMARY KEY (`id`, `workshop_suscription_id`, `payment_receipt_id`),
  CONSTRAINT `fk_payment_receipt_suscription_payment_receipt1`
    FOREIGN KEY (`payment_receipt_id`)
    REFERENCES `tutaller`.`payment_receipt` (`id`)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION,
  CONSTRAINT `fk_payment_receipt_suscription_workshop_suscription1`
    FOREIGN KEY (`workshop_suscription_id`)
    REFERENCES `tutaller`.`workshop_suscription` (`id`)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION)
ENGINE = InnoDB
DEFAULT CHARACTER SET = utf8;


-- -----------------------------------------------------
-- Table `tutaller`.`workshop_ad`
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS `tutaller`.`workshop_ad` (
  `id` INT(11) NOT NULL AUTO_INCREMENT,
  `workshop_office_id` SMALLINT(6) NOT NULL,
  `workshop_ad_bid` INT(11) NOT NULL,
  `image_id` INT(11) NOT NULL,
  `workshop_ad_name` VARCHAR(45) NOT NULL,
  `workshop_ad_money_spent` INT(11) NOT NULL,
  PRIMARY KEY (`id`),
  CONSTRAINT `fk_workshop_ad_image1`
    FOREIGN KEY (`image_id`)
    REFERENCES `tutaller`.`image` (`id`)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION,
  CONSTRAINT `fk_workshop_ad_workshop_office1`
    FOREIGN KEY (`workshop_office_id`)
    REFERENCES `tutaller`.`workshop_office` (`id`)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION)
ENGINE = InnoDB
DEFAULT CHARACTER SET = utf8;


-- -----------------------------------------------------
-- Table `tutaller`.`payment_receipt_workshop_ad`
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS `tutaller`.`payment_receipt_workshop_ad` (
  `id` INT(11) NOT NULL AUTO_INCREMENT,
  `workshop_ad_id` INT(11) NOT NULL,
  `payment_receipt_id` INT(11) NOT NULL,
  PRIMARY KEY (`id`),
  CONSTRAINT `fk_payment_receipt_workshop_ad_payment_receipt1`
    FOREIGN KEY (`payment_receipt_id`)
    REFERENCES `tutaller`.`payment_receipt` (`id`)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION,
  CONSTRAINT `fk_payment_receipt_workshop_ad_workshop_ad1`
    FOREIGN KEY (`workshop_ad_id`)
    REFERENCES `tutaller`.`workshop_ad` (`id`)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION)
ENGINE = InnoDB
DEFAULT CHARACTER SET = utf8;


-- -----------------------------------------------------
-- Table `tutaller`.`postulation`
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS `tutaller`.`postulation` (
  `id` INT(11) NOT NULL AUTO_INCREMENT,
  `user_user_rut` INT(11) NOT NULL,
  `postulation_current_status` VARCHAR(45) NOT NULL,
  `postulation_message` VARCHAR(99) NOT NULL,
  `workshop_id` SMALLINT(6) NOT NULL,
  `postulation_date_time` DATETIME NOT NULL,
  PRIMARY KEY (`id`),
  CONSTRAINT `fk_postulation_workshop1`
    FOREIGN KEY (`workshop_id`)
    REFERENCES `tutaller`.`workshop` (`id`)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION,
  CONSTRAINT `fk_postulations_user1`
    FOREIGN KEY (`user_user_rut`)
    REFERENCES `tutaller`.`user` (`user_rut`)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION)
ENGINE = InnoDB
AUTO_INCREMENT = 3
DEFAULT CHARACTER SET = utf8;


-- -----------------------------------------------------
-- Table `tutaller`.`usability_questionnaire`
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS `tutaller`.`usability_questionnaire` (
  `id` INT(11) NOT NULL AUTO_INCREMENT,
  `usability_questionnaire_name` VARCHAR(45) NOT NULL,
  `usability_questionnaire_description` VARCHAR(580) NOT NULL,
  PRIMARY KEY (`id`))
ENGINE = InnoDB
DEFAULT CHARACTER SET = utf8;


-- -----------------------------------------------------
-- Table `tutaller`.`questionnaire_question`
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS `tutaller`.`questionnaire_question` (
  `id` INT(11) NOT NULL AUTO_INCREMENT,
  `usability_questionnaire_id` INT(11) NOT NULL,
  `questionnaire_question_name` VARCHAR(45) NOT NULL,
  `questionnaire_question_type` VARCHAR(45) NOT NULL,
  PRIMARY KEY (`id`),
  CONSTRAINT `fk_questionnaire_questions_usability_questionnaires1`
    FOREIGN KEY (`usability_questionnaire_id`)
    REFERENCES `tutaller`.`usability_questionnaire` (`id`)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION)
ENGINE = InnoDB
DEFAULT CHARACTER SET = utf8;


-- -----------------------------------------------------
-- Table `tutaller`.`questionnaire_question_answer`
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS `tutaller`.`questionnaire_question_answer` (
  `id` INT(11) NOT NULL AUTO_INCREMENT,
  `user_user_rut` INT(11) NOT NULL,
  `questionnaire_question_id` INT(11) NOT NULL,
  `questionnaire_response` VARCHAR(255) NOT NULL,
  PRIMARY KEY (`id`),
  CONSTRAINT `fk_questionnaire_question_answer_questionnaire_question1`
    FOREIGN KEY (`questionnaire_question_id`)
    REFERENCES `tutaller`.`questionnaire_question` (`id`)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION,
  CONSTRAINT `fk_questionnaire_question_answer_user1`
    FOREIGN KEY (`user_user_rut`)
    REFERENCES `tutaller`.`user` (`user_rut`)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION)
ENGINE = InnoDB
DEFAULT CHARACTER SET = utf8;


-- -----------------------------------------------------
-- Table `tutaller`.`questionnaire_question_item`
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS `tutaller`.`questionnaire_question_item` (
  `id` INT(11) NOT NULL,
  `questionnaire_question_id` INT(11) NOT NULL,
  `questionnarie_question_item_statement` VARCHAR(580) NOT NULL,
  PRIMARY KEY (`id`),
  CONSTRAINT `fk_questionnarie_question_item_questionnaire_question1`
    FOREIGN KEY (`questionnaire_question_id`)
    REFERENCES `tutaller`.`questionnaire_question` (`id`)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION)
ENGINE = InnoDB
DEFAULT CHARACTER SET = utf8;


-- -----------------------------------------------------
-- Table `tutaller`.`workshop_office_attention`
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS `tutaller`.`workshop_office_attention` (
  `id` INT(11) NOT NULL AUTO_INCREMENT,
  `workshop_office_id` SMALLINT(6) NOT NULL,
  `workshop_office_attention_day` VARCHAR(10) NOT NULL,
  `workshop_office_attention_aperture_time` TIME NOT NULL,
  `workshop_office_attention_departure_time` TIME NOT NULL,
  PRIMARY KEY (`id`),
  CONSTRAINT `fk_workshop_office_attention_time_workshop_office1`
    FOREIGN KEY (`workshop_office_id`)
    REFERENCES `tutaller`.`workshop_office` (`id`)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION)
ENGINE = InnoDB
AUTO_INCREMENT = 31
DEFAULT CHARACTER SET = utf8;


-- -----------------------------------------------------
-- Table `tutaller`.`reservation_attention`
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS `tutaller`.`reservation_attention` (
  `id` INT(11) NOT NULL AUTO_INCREMENT,
  `workshop_office_attention_time_id` INT(11) NOT NULL,
  `user_user_rut` INT(11) NOT NULL,
  `status` VARCHAR(45) NOT NULL,
  PRIMARY KEY (`id`),
  CONSTRAINT `fk_reservation_attention_user1`
    FOREIGN KEY (`user_user_rut`)
    REFERENCES `tutaller`.`user` (`user_rut`)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION,
  CONSTRAINT `fk_reservation_attention_workshop_office_attention_time1`
    FOREIGN KEY (`workshop_office_attention_time_id`)
    REFERENCES `tutaller`.`workshop_office_attention` (`id`)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION)
ENGINE = InnoDB
DEFAULT CHARACTER SET = utf8;


-- -----------------------------------------------------
-- Table `tutaller`.`user_usability_questionnaire`
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS `tutaller`.`user_usability_questionnaire` (
  `id` INT(11) NOT NULL,
  `user_user_rut` INT(11) NOT NULL,
  `usability_questionnaire_id` INT(11) NOT NULL,
  `status` VARCHAR(45) NOT NULL,
  PRIMARY KEY (`id`),
  CONSTRAINT `fk_user_usability_questionnaire_usability_questionnaire1`
    FOREIGN KEY (`usability_questionnaire_id`)
    REFERENCES `tutaller`.`usability_questionnaire` (`id`)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION,
  CONSTRAINT `fk_user_usability_questionnaire_user1`
    FOREIGN KEY (`user_user_rut`)
    REFERENCES `tutaller`.`user` (`user_rut`)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION)
ENGINE = InnoDB
DEFAULT CHARACTER SET = utf8;


-- -----------------------------------------------------
-- Table `tutaller`.`workshop_office_evaluation`
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS `tutaller`.`workshop_office_evaluation` (
  `id` INT(11) NOT NULL AUTO_INCREMENT,
  `workshop_evaluation_rating` TINYINT(5) NOT NULL,
  `workshop_evaluation_review` VARCHAR(580) NOT NULL,
  `user_user_rut` INT(11) NOT NULL,
  `workshop_office_id` SMALLINT(6) NOT NULL,
  PRIMARY KEY (`id`),
  CONSTRAINT `fk_workshop_office_evaluation_user1`
    FOREIGN KEY (`user_user_rut`)
    REFERENCES `tutaller`.`user` (`user_rut`)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION,
  CONSTRAINT `fk_workshop_office_evaluation_workshop_office1`
    FOREIGN KEY (`workshop_office_id`)
    REFERENCES `tutaller`.`workshop_office` (`id`)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION)
ENGINE = InnoDB
DEFAULT CHARACTER SET = utf8;


-- -----------------------------------------------------
-- Table `tutaller`.`workshop_office_service_advance`
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS `tutaller`.`workshop_office_service_advance` (
  `id` INT(11) NOT NULL AUTO_INCREMENT,
  `image_id` INT(11) NOT NULL,
  `workshop_office_work_id` INT(11) NOT NULL,
  `workshop_office_service_advance_description` VARCHAR(255) NOT NULL,
  PRIMARY KEY (`id`),
  CONSTRAINT `fk_workshop_office_service_advance_image1`
    FOREIGN KEY (`image_id`)
    REFERENCES `tutaller`.`image` (`id`)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION,
  CONSTRAINT `fk_workshop_office_service_advance_workshop_office_work1`
    FOREIGN KEY (`workshop_office_work_id`)
    REFERENCES `tutaller`.`workshop_office_work` (`id`)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION)
ENGINE = InnoDB
DEFAULT CHARACTER SET = utf8;


-- -----------------------------------------------------
-- Table `tutaller`.`workshop_office_service_payment_receipt`
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS `tutaller`.`workshop_office_service_payment_receipt` (
  `id` INT(11) NOT NULL AUTO_INCREMENT,
  `workshop_office_service_id` INT(11) NOT NULL,
  `payment_receipt_id` INT(11) NOT NULL,
  PRIMARY KEY (`id`),
  CONSTRAINT `fk_workshop_office_service_payment_receipt_payment_receipt1`
    FOREIGN KEY (`payment_receipt_id`)
    REFERENCES `tutaller`.`payment_receipt` (`id`)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION,
  CONSTRAINT `fk_workshop_office_service_payment_receipt_workshop_office_se1`
    FOREIGN KEY (`workshop_office_service_id`)
    REFERENCES `tutaller`.`workshop_office_service` (`id`)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION)
ENGINE = InnoDB
DEFAULT CHARACTER SET = utf8;


-- -----------------------------------------------------
-- Table `tutaller`.`workshop_office_work_case`
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS `tutaller`.`workshop_office_work_case` (
  `idworkshop_office_work_case` INT(11) NOT NULL,
  `workshop_office_work_case_msg` VARCHAR(255) NOT NULL,
  `case_current_status` VARCHAR(45) NOT NULL,
  `workshop_office_work_id` INT(11) NOT NULL,
  `user_user_rut` INT(11) NOT NULL,
  PRIMARY KEY (`idworkshop_office_work_case`),
  CONSTRAINT `fk_workshop_office_work_case_user1`
    FOREIGN KEY (`user_user_rut`)
    REFERENCES `tutaller`.`user` (`user_rut`)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION,
  CONSTRAINT `fk_workshop_office_work_case_workshop_office_work1`
    FOREIGN KEY (`workshop_office_work_id`)
    REFERENCES `tutaller`.`workshop_office_work` (`id`)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION)
ENGINE = InnoDB
DEFAULT CHARACTER SET = utf8;


-- -----------------------------------------------------
-- Table `tutaller`.`workshop_office_work_milestone`
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS `tutaller`.`workshop_office_work_milestone` (
  `id` INT(11) NOT NULL AUTO_INCREMENT,
  `workshop_office_work_id` INT(11) NOT NULL,
  `workshop_office_work_milestone_name` VARCHAR(45) NOT NULL,
  `workshop_office_work_milestone_description` VARCHAR(99) NOT NULL,
  `workshop_office_work_milestone_status` VARCHAR(45) NOT NULL,
  PRIMARY KEY (`id`),
  CONSTRAINT `fk_workshop_office_work_milestone_workshop_office_work1`
    FOREIGN KEY (`workshop_office_work_id`)
    REFERENCES `tutaller`.`workshop_office_work` (`id`)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION)
ENGINE = InnoDB
DEFAULT CHARACTER SET = utf8;

INSERT INTO `user_type` (`id`,`user_type_name`,`user_type_description`) VALUES (1,'admin','system administrator');
INSERT INTO `user_type` (`id`,`user_type_name`,`user_type_description`) VALUES (2,'user','system user');
INSERT INTO `user_type` (`id`,`user_type_name`,`user_type_description`) VALUES (3,'adminworkshop','workshop administrator');
INSERT INTO `user_type` (`id`,`user_type_name`,`user_type_description`) VALUES (4,'technicianworkshop','workshop office technician');
INSERT INTO `country` (`id`,`country_name`) VALUES (1,'Chile');
INSERT INTO `region` (`id`,`country_id`,`region_name`) VALUES (1,1,'Arica y Parinacota');
INSERT INTO `region` (`id`,`country_id`,`region_name`) VALUES (2,1,'Región de Tarapacá');
INSERT INTO `region` (`id`,`country_id`,`region_name`) VALUES (3,1,'Región de Antofagasta');
INSERT INTO `region` (`id`,`country_id`,`region_name`) VALUES (4,1,'Región de Atacama');
INSERT INTO `region` (`id`,`country_id`,`region_name`) VALUES (5,1,'Región de Coquimbo');
INSERT INTO `region` (`id`,`country_id`,`region_name`) VALUES (6,1,'Región de Valparaíso');
INSERT INTO `region` (`id`,`country_id`,`region_name`) VALUES (7,1,'Región Metropolitana de Santiago');
INSERT INTO `region` (`id`,`country_id`,`region_name`) VALUES (8,1,'Región del Libertador General Bernardo O’Higgins');
INSERT INTO `region` (`id`,`country_id`,`region_name`) VALUES (9,1,'Región del Maule');
INSERT INTO `region` (`id`,`country_id`,`region_name`) VALUES (10,1,'Región del Ñuble');
INSERT INTO `region` (`id`,`country_id`,`region_name`) VALUES (11,1,'Región del Biobío');
INSERT INTO `region` (`id`,`country_id`,`region_name`) VALUES (12,1,'Región de La Araucanía');
INSERT INTO `region` (`id`,`country_id`,`region_name`) VALUES (13,1,'Región de Los Ríos');
INSERT INTO `region` (`id`,`country_id`,`region_name`) VALUES (14,1,'Región de Los Lagos');
INSERT INTO `region` (`id`,`country_id`,`region_name`) VALUES (15,1,'Región de Aysén del General Carlos Ibáñez del Campo');
INSERT INTO `region` (`id`,`country_id`,`region_name`) VALUES (16,1,'Región de Magallanes y la Antártica Chilena');
INSERT INTO `commune` (`id`,`region_id`,`commune_name`) VALUES (2,7,'Alhué');
INSERT INTO `commune` (`id`,`region_id`,`commune_name`) VALUES (3,7,'Buin');
INSERT INTO `commune` (`id`,`region_id`,`commune_name`) VALUES (4,7,'Calera de Tango');
INSERT INTO `commune` (`id`,`region_id`,`commune_name`) VALUES (5,7,'Cerrillos');
INSERT INTO `commune` (`id`,`region_id`,`commune_name`) VALUES (6,7,'Cerro Navia');
INSERT INTO `commune` (`id`,`region_id`,`commune_name`) VALUES (7,7,'Colina');
INSERT INTO `commune` (`id`,`region_id`,`commune_name`) VALUES (8,7,'Conchalí');
INSERT INTO `commune` (`id`,`region_id`,`commune_name`) VALUES (9,7,'Curacaví');
INSERT INTO `commune` (`id`,`region_id`,`commune_name`) VALUES (10,7,'El Bosque');
INSERT INTO `commune` (`id`,`region_id`,`commune_name`) VALUES (11,7,'El Monte');
INSERT INTO `commune` (`id`,`region_id`,`commune_name`) VALUES (12,7,'Estación Central');
INSERT INTO `commune` (`id`,`region_id`,`commune_name`) VALUES (13,7,'Huechuraba');
INSERT INTO `commune` (`id`,`region_id`,`commune_name`) VALUES (14,7,'Independencia');
INSERT INTO `commune` (`id`,`region_id`,`commune_name`) VALUES (15,7,'Isla de Maipo');
INSERT INTO `commune` (`id`,`region_id`,`commune_name`) VALUES (16,7,'La Cisterna');
INSERT INTO `commune` (`id`,`region_id`,`commune_name`) VALUES (17,7,'La Florida');
INSERT INTO `commune` (`id`,`region_id`,`commune_name`) VALUES (18,7,'La Granja');
INSERT INTO `commune` (`id`,`region_id`,`commune_name`) VALUES (19,7,'La Pintana');
INSERT INTO `commune` (`id`,`region_id`,`commune_name`) VALUES (20,7,'La Reina');
INSERT INTO `commune` (`id`,`region_id`,`commune_name`) VALUES (21,7,'Lampa');
INSERT INTO `commune` (`id`,`region_id`,`commune_name`) VALUES (22,7,'Las Condes');
INSERT INTO `commune` (`id`,`region_id`,`commune_name`) VALUES (23,7,'Lo Barnechea');
INSERT INTO `commune` (`id`,`region_id`,`commune_name`) VALUES (24,7,'Lo Espejo');
INSERT INTO `commune` (`id`,`region_id`,`commune_name`) VALUES (25,7,'Lo Prado');
INSERT INTO `commune` (`id`,`region_id`,`commune_name`) VALUES (26,7,'Macul');
INSERT INTO `commune` (`id`,`region_id`,`commune_name`) VALUES (27,7,'Maipú');
INSERT INTO `commune` (`id`,`region_id`,`commune_name`) VALUES (28,7,'María Pinto');
INSERT INTO `commune` (`id`,`region_id`,`commune_name`) VALUES (29,7,'Melipilla');
INSERT INTO `commune` (`id`,`region_id`,`commune_name`) VALUES (30,7,'Ñuñoa');
INSERT INTO `commune` (`id`,`region_id`,`commune_name`) VALUES (31,7,'Padre Hurtado');
INSERT INTO `commune` (`id`,`region_id`,`commune_name`) VALUES (32,7,'Paine');
INSERT INTO `commune` (`id`,`region_id`,`commune_name`) VALUES (33,7,'Pedro Aguirre Cerda');
INSERT INTO `commune` (`id`,`region_id`,`commune_name`) VALUES (34,7,'Peñaflor');
INSERT INTO `commune` (`id`,`region_id`,`commune_name`) VALUES (35,7,'Peñalolén');
INSERT INTO `commune` (`id`,`region_id`,`commune_name`) VALUES (36,7,'Pirque');
INSERT INTO `commune` (`id`,`region_id`,`commune_name`) VALUES (37,7,'Providencia');
INSERT INTO `commune` (`id`,`region_id`,`commune_name`) VALUES (38,7,'Pudahuel');
INSERT INTO `commune` (`id`,`region_id`,`commune_name`) VALUES (39,7,'Puente Alto');
INSERT INTO `commune` (`id`,`region_id`,`commune_name`) VALUES (40,7,'Quilicura');
INSERT INTO `commune` (`id`,`region_id`,`commune_name`) VALUES (41,7,'Quinta Normal');
INSERT INTO `commune` (`id`,`region_id`,`commune_name`) VALUES (42,7,'Recoleta');
INSERT INTO `commune` (`id`,`region_id`,`commune_name`) VALUES (43,7,'Renca');
INSERT INTO `commune` (`id`,`region_id`,`commune_name`) VALUES (44,7,'San Bernardo');
INSERT INTO `commune` (`id`,`region_id`,`commune_name`) VALUES (45,7,'San Joaquín');
INSERT INTO `commune` (`id`,`region_id`,`commune_name`) VALUES (46,7,'San José de Maipo');
INSERT INTO `commune` (`id`,`region_id`,`commune_name`) VALUES (47,7,'San Miguel');
INSERT INTO `commune` (`id`,`region_id`,`commune_name`) VALUES (48,7,'San Pedro');
INSERT INTO `commune` (`id`,`region_id`,`commune_name`) VALUES (49,7,'San Ramón');
INSERT INTO `commune` (`id`,`region_id`,`commune_name`) VALUES (50,7,'Santiago');
INSERT INTO `commune` (`id`,`region_id`,`commune_name`) VALUES (51,7,'Talagante');
INSERT INTO `commune` (`id`,`region_id`,`commune_name`) VALUES (52,7,'Tiltil');
INSERT INTO `commune` (`id`,`region_id`,`commune_name`) VALUES (53,7,'Vitacura');
INSERT INTO `offer` (`id`,`offer_name`,`offer_discount`) VALUES (1,'none',0);
INSERT INTO `workshop_suscription` (`id`,`offer_id`,`name`,`price`,`description`) VALUES (1,1,'unsubscribed',0,'without subscription');
INSERT INTO `workshop_suscription` (`id`,`offer_id`,`name`,`price`,`description`) VALUES (2,1,'basic',3533,'monthly basic plan');

SET SQL_MODE=@OLD_SQL_MODE;
SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS;
SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS;
