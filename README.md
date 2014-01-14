php-auth-crypt
==============

スマホアプリとセキュアに通信するための認証・暗号化モジュール

ファイル
---------
* user.sql -- MySQL ユーザ管理テーブル
* auth.php -- 認証・暗号化モジュール

### テーブルの構造 user.sql

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
    ) ENGINE=InnoDB  DEFAULT CHARSET=utf8 COMMENT='ユーザテーブル' AUTO_INCREMENT=1;

### プロトコル概要
---------

ログイン
* 端末からサーバにログイン -- 端末内の公開鍵を使ってJSON（UUID、共通鍵、unixtime）をサーバに送信
* サーバで受け取った暗号化されたJSONデータを秘密鍵で複合する -- UUID、共通鍵、unixtimeをDBとセッションに保存
* サーバでuser_idを発行する -- 端末にセッションID送信

リクエスト・レスポンス
* 端末からリクエストを送る -- 共通鍵を使ってJSONリクエスト（リクエスト、unixtime）とセッションIDを暗号化しサーバに送信
* サーバで受け取った暗号化されたJSONリクエストをセッション内の共通鍵で復号化する
* 復号化されたリクエストとセッション内のuser_idで処理を行う
* 結果のJSONレスポンス（レスポンス、unixtime）を共通鍵で暗号化し端末に返信する
