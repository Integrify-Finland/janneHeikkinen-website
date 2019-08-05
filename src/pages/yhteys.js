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
