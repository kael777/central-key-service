-- 清除 QA 第一輪遺留的「空代碼幽靈系統」與舊測試資料。
-- 先備份：mysqldump -u root -p cms_key > cms_key-backup.sql
-- 只刪資料，不動 audit_log（保留稽核紀錄）。

-- 1) 空代碼幽靈系統（舊版 bug 產生，UI 無法操作）
DELETE FROM key_versions WHERE system_code = '';
DELETE FROM systems WHERE code = '';

-- 2) 選擇性：清掉 QA 測試建立的系統（確認不再需要後再執行）
-- DELETE FROM key_versions WHERE system_code IN ('SYS-QA1','SYS-QA3','SYS-QA5','SYS-RACE','SYS-BIG3','SYS-TRIM','SYS:Q');
-- DELETE FROM systems WHERE code IN ('SYS-QA1','SYS-QA3','SYS-QA5','SYS-RACE','SYS-BIG3','SYS-TRIM','SYS:Q');

-- 3) 驗證
SELECT code, name, status FROM systems WHERE code = '';
SELECT COUNT(*) AS ghost_versions FROM key_versions WHERE system_code = '';
