node('maven') {
   stage('Preparation') {
      checkout scm
   }
   stage('Build') {
      sh "mvn -Dmaven.test.failure.ignore clean package"
   }
   stage('Results') {
      archive 'target/*.jar'
      archive 'target/*.hpi'
   }
}
