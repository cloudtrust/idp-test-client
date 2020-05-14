pipeline {
  agent any
  options {
    timestamps()
    timeout(time: 3600, unit: 'SECONDS')
  }
  parameters {
    string(name: 'CREATE_RELEASE', defaultValue: 'false')
    string(name: 'VERSION', defaultValue: '')
    string(name: 'REPO_URL', defaultValue: '')
  }
  stages {
    stage('Build') {
      agent {
        label 'jenkins-slave-maven-ct'
      }
      steps {
        script {
          sh 'printenv'
          withCredentials([usernamePassword(credentialsId: 'sonarqube', usernameVariable: 'USER', passwordVariable: 'PASS')]) {
            def sonar_opts = "\"-Dsonar.login=${USER}\" \"-Dsonar.password=${PASS}\""
            sh """
              mvn -B -T4 clean package \
                spotbugs:spotbugs pmd:pmd dependency-check:check \
                -Dsonar.java.spotbugs.reportPaths=target/spotbugsXml.xml \
                -Dsonar.java.pmd.reportPaths=target/pmd.xml \
                ${sonar_opts} \
                sonar:sonar
            """
          }
          if (params.CREATE_RELEASE == "true"){
            echo "creating release ${VERSION} and uploading it to ${REPO_URL}"
            // upload to repo
            withCredentials([usernamePassword(credentialsId: 'cloudtrust-cicd-artifactory-opaque', usernameVariable: 'USR', passwordVariable: 'PASSWD')]){
              sh """
                cd target/
                mv IdPTestClient.jar IdPTestClient-${params.VERSION}.jar
                curl --fail -k -u"${USR}:${PASSWD}" -T "IdPTestClient-${params.VERSION}.jar" --keepalive-time 2 "${REPO_URL}/IdPTestClient-${params.VERSION}.jar"
              """
            }
            if (!env.TAG_NAME && env.TAG_NAME != params.VERSION) {
              def git_url = "${env.GIT_URL}".replaceFirst("^(http[s]?://www\\.|http[s]?://|www\\.)","")
              withCredentials([usernamePassword(credentialsId: "support-triustid-ch",
                  passwordVariable: 'PASSWD',
                  usernameVariable: 'USR')]) {
                sh("git config user.email 'support@trustid.ch'")
                sh("git config user.name 'ci'")
                sh("git tag ${VERSION} -m 'CI'")
                sh("git push https://${USR}:${PASSWD}@${git_url} --tags")
              }
            } else {
              echo "Tag ${env.TAG_NAME} already exists. Skipping."
            }
            echo "release ${VERSION} available at ${REPO_URL}/${APP}-${params.VERSION}.tar.gz"
          }
        }
      }
    }
  }
}
