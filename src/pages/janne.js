import React from "react"
import { graphql } from "gatsby"

import Layout from "../components/Layout"
import SEO from "../components/SEO"
import Resume from "../components/Resume"
import AboutTextBlock from "../components/About-text-block"
import Section from "../components/Section"

import Header from "../components/Header";

const Janne = ({ data }) => {
  const { resume, DetailsAboutMe, aboutMe } = data
  const revertedDetails = DetailsAboutMe.edges.reverse()
  return (
    <Layout>
      <SEO title="Janne" />
      <Header
      isAbout={true}
      Kotipaikka={aboutMe.kotiPaikka}
      Syntynyt={aboutMe.syntynyt}
      Perhe={aboutMe.perhe}
      Sotilasarvo_aselinja={aboutMe.sotilasArvo}
      Ammatti={aboutMe.ammatti}
      Harrastukset={aboutMe.harrastukset}
      Koulutus={aboutMe.koulutus}
      Luottamustehtava={aboutMe.luottamustehtava}
      />
      <Section>
        {revertedDetails.map(({ node }, i) => {
          return i % 2 !== 0 ? (
            <AboutTextBlock
              title={node.title}
              text={node.description.description}
              icon={`https:${node.image.file.url}`}
            />
          ) : (
            <AboutTextBlock
              title={node.title}
              text={node.description.description}
              isLeft
              icon={`https:${node.image.file.url}`}
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
          image {
            file {
              url
            }
          }
          description {
            description
          }
        }
      }
    }
  }
`
