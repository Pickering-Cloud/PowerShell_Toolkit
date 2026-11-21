Invoke-Sqlcmd -Query 'SELECT * FROM Users WHERE Id = $(Id)' -Variable "Id=$id"
$cmd.CommandText = 'SELECT * FROM Users WHERE Name = @name'
