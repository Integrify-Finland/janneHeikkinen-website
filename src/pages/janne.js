import React from "react"
import { graphql } from "gatsby"

import Layout from "../components/Layout"
import SEO from "../components/SEO"
import Resume from "../components/Resume"

const Janne = ({ data }) => {
  const { resume } = data

  return (
    <Layout>
      <SEO title="Janne" />
      <Resume
        opinnot={resume.opinnot}
        varusmies={resume.varusmiespalvelus}
        tyo={resume.tyoelamassa}
        luottamus={resume.luottamustoimet}
      />
    </Layout>
  )
}

export default Janne

export const query = graphql`
  query {
    resume: contentfulResume {
      opinnot
      varusmiespalvelus
      tyoelamassa
      luottamustoimet
    }
    aboutMe: contentfulAboutMe {
      kotiPaikka
      syntynyt
      perhe
      sotilasarvo
      ammatti
      harrastukset
      koulutus
      luottamustehtava
    }

    DetailsAboutMe: allContentfulDetailsAboutMe {
      edges {
        node {
          title
          description {
            description
          }
        }
      }
    }
  }
`
