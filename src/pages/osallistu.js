import React from "react"
import { graphql } from "gatsby"

import Layout from "../components/Layout"
import SEO from "../components/SEO"
import RegisterForm from "../components/RegisterForm"
import Section from "../components/Section"

import "./styles.scss"

const Osallistu = () => {
  return (
    <Layout>
      <SEO title="Osallistu" />
      <Section>
        <div className="osallistu">
          <h1 className="osallistu__title">Osallistu</h1>
          <RegisterForm />
        </div>
      </Section>
    </Layout>
  )
}

export default Osallistu