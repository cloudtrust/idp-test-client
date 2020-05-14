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
  environment{
    APP="IdpTestClient"
  }
  stages {
    stage('Build') {
      agent {
        label 'jenkins-slave-maven-ct'
      }
      steps {
        script {
          sh 'printenv'
          withCredentials([usernamePassword(credentialsId: 'cloudtrust-cicd-sonarqube', usernameVariable: 'USER', passwordVariable: 'PASSWD')]) {
            def sonar_opts = "\"-Dsonar.login=${USER}\" \"-Dsonar.password=${PASSWD}\""
            sh """
              mvn -B -T4 clean package \
                spotbugs:spotbugs pmd:pmd dependency-check:check \
                -Dsonar.java.spotbugs.reportPaths=target/spotbugsXml.xml \
                -Dsonar.java.pmd.reportPaths=target/pmd.xml \
                ${sonar_opts} \
                sonar:sonar
            """
          }
          if (params.CREATE_RELEASE == "true") {
            echo "creating release ${VERSION} and uploading it to ${REPO_URL}"
            // upload to repo
            withCredentials([usernamePassword(credentialsId: 'cloudtrust-cicd-artifactory-opaque', usernameVariable: 'USR', passwordVariable: 'PASSWD')]){
              sh """
                cd target/
                mv ${APP}.jar ${APP}-${params.VERSION}.jar
                curl --fail -k -u"${USR}:${PASSWD}" -T "${APP}-${params.VERSION}.jar" --keepalive-time 2 "${REPO_URL}/${APP}-${params.VERSION}.jar"
              """
            }
            if (!env.TAG_NAME && env.TAG_NAME != params.VERSION) {
              withCredentials([usernamePassword(credentialsId: "cloudtrust-cicd-support-triustid-ch",
                  usernameVariable: 'USR',
                  passwordVariable: 'PASSWD')]) {
                def git_url = "${env.GIT_URL}".replaceFirst("^(http[s]?://www\\.|http[s]?://|www\\.)","")
                sh("git config --global user.email 'ci@dev.null'")
                sh("git config --global user.name 'ci'")
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
