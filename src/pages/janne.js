import React from "react"
import { graphql } from "gatsby"

import Layout from "../components/Layout"
import SEO from "../components/SEO"
import Resume from "../components/Resume"
import AboutTextBlock from "../components/About-text-block"
import Section from "../components/Section"

import imageFile from "../images/gatsby-icon.png"
import astro from "../images/gatsby-astronaut.png"

const Janne = ({ data }) => {
  const { resume, DetailsAboutMe } = data
  const revertedDetails = DetailsAboutMe.edges.reverse()
  return (
    <Layout>
      <SEO title="Janne" />
      <Section>
        {revertedDetails.map(({ node }, i) => {
          return i % 2 !== 0 ? (
            <AboutTextBlock
              title={node.title}
              text={node.description.description}
              icon={imageFile}
            />
          ) : (
            <AboutTextBlock
              title={node.title}
              text={node.description.description}
              isLeft
              icon={astro}
            />
          )
        })}
      </Section>
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
