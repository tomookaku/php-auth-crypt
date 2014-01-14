--
-- テーブルの構造 `user`
--

CREATE TABLE IF NOT EXISTS `user` (
  `id` bigint(16) unsigned NOT NULL AUTO_INCREMENT,
  `user_id` varchar(16) CHARACTER SET ascii DEFAULT NULL,
  `uuid` varchar(255) NOT NULL DEFAULT '' COMMENT 'アプリクライアントで生成されるUUID',
  `time` int(11) unsigned NOT NULL,
  `up_date` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新日',
  `reg_date` datetime NOT NULL COMMENT '登録日',
  PRIMARY KEY (`id`),
  UNIQUE KEY `uuid` (`uuid`),
  UNIQUE KEY `user_id` (`user_id`)
) ENGINE=InnoDB  DEFAULT CHARSET=utf8 COMMENT='ユーザテーブル' AUTO_INCREMENT=1 ;