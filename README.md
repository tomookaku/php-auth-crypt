php-auth-crypt
==============

スマホアプリとセキュアに通信するための認証・暗号化モジュール

ファイル
---------
* user.sql -- MySQL ユーザ管理テーブル
* auth.php -- 認証・暗号化モジュール

### テーブルの構造 user.sql

    mysql> desc user;
    +----------+---------------------+------+-----+-------------------+-----------------------------+
    | Field    | Type                | Null | Key | Default           | Extra                       |
    +----------+---------------------+------+-----+-------------------+-----------------------------+
    | id       | bigint(16) unsigned | NO   | PRI | NULL              | auto_increment              |
    | user_id  | varchar(16)         | YES  | UNI | NULL              |                             |
    | uuid     | varchar(255)        | NO   | UNI |                   |                             |
    | time     | int(11) unsigned    | NO   |     | NULL              |                             |
    | up_date  | timestamp           | NO   |     | CURRENT_TIMESTAMP | on update CURRENT_TIMESTAMP |
    | reg_date | datetime            | NO   |     | NULL              |                             |
    +----------+---------------------+------+-----+-------------------+-----------------------------+
    6 rows in set (0.00 sec)

### プロトコル概要
---------

ログイン
* 端末からサーバにログイン -- 端末内の「公開鍵」を使ってJSON（UUID、共通鍵、unixtime）をサーバに送信
* サーバで受け取った暗号化されたJSONデータを「秘密鍵」で複合する -- UUID、共通鍵、unixtimeをDBとセッションに保存
* サーバでuser_idを発行する -- 端末にセッションID送信

リクエスト・レスポンス
* 端末からリクエストを送る -- 「共通鍵」を使ってJSONリクエスト（リクエスト、unixtime）とセッションIDを暗号化しサーバに送信
* サーバで受け取った暗号化されたJSONリクエストをセッション内の「共通鍵」で復号化する
* 復号化されたリクエストとセッション内のuser_idで処理を行う
* 結果のJSONレスポンス（レスポンス、unixtime）を「共通鍵」で暗号化し端末に返信する
