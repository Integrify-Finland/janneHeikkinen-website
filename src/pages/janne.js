import React from "react"
import { graphql } from "gatsby"

import Layout from "../components/Layout"
import SEO from "../components/SEO"

const Janne = ({ data }) => {
  const { aboutMe, DetailsAboutMe, resume } = data

  return (
    <Layout>
      <SEO title="Janne" />
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
