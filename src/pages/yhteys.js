import React from "react"
import { graphql } from "gatsby"

import Layout from "../components/Layout"
import SEO from "../components/SEO"
import ContactForm from "../components/ContactForm"
import Section from "../components/Section"

const Yhteys = ({ data }) => {
  //   const { contactUs } = data

  return (
    <Layout>
      <SEO title="Yhteys" />
      <Section>
        <ContactForm />
        <p
          style={{
            display: "flex",
            flexWrap: "wrap",
            justifyContent: "center",
            color: "#023b56",
          }}
        >
          <span style={{ marginRight: "1rem" }}>
            <strong>Puhelin: </strong>
            +358 (0) 40 5554263
          </span>
          <span>
            <strong>Sähköposti: </strong>
            janne@janneheikkinen.fi
          </span>
        </p>
      </Section>
    </Layout>
  )
}

export default Yhteys

export const query = graphql`
  query {
    contactUs: allContentfulContactUs {
      edges {
        node {
          name
          title
          phoneNumber
          email
        }
      }
    }
  }
`
