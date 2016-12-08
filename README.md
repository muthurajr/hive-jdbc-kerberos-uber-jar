# hive-jdbc-kerberos-uber-jar
Standalone/Uber jar to connect to Hive in Kerberos Cluster with Jdbc using password [built currently using CDH libraries]

Sometimes we might need tools like DbVizualizer to connect to Hive. Hive-standalone jar can be used to establish the connectivity but in case of Kerberos Cluster, ticket has to be generated ahead before connecting and accessing multiple hive jdbc within same application makes difficult due to ticket caching.

Inorder to solve the above problems, HiveDriver is customized with security addition and uber jar is created for simplicity.

Usage:
  1. Built the standalone jar using the project and add to the respective tool
  2. Use com.hive.jdbc.PreAuthenticatedHiveDriver as the driver class
  3. Url : jdbc:hive2://\<hiveserver2\>:10000/default;krb5_kdc=\<kerberos_admin_server\>;principal=hive/\<hiverserver2\>@\<krb5realm\>;auth=kerberos;kerberosAuthType=fromSubject;
  4. User and Password as per the tool
  
