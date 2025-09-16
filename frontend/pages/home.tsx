// pages/home.tsx
import { withAuth } from "../utils/withAuth";
import { useRouter } from "next/router";
import styles from "../styles/Home.module.css";
import { GetServerSideProps } from "next";
import ConnectPage from "./connect"; // ✅ import ConnectPage

const Home = () => {
  const router = useRouter();

  const handleLogout = async () => {
    try {
      const res = await fetch("http://localhost:4000/auth/logout", {
        method: "POST",
        credentials: 'include', 
      });

      if (res.ok) {
        router.push("/login");
      } else {
        console.error("Logout failed");
      }
    } catch (error) {
      console.error("An error occurred during logout:", error);
    }
  };

  return (
    <div className={styles.container}>
      {/* ✅ Header section */}
      <header className={styles.header}>
        <h1 className={styles.logo}>Welcome to your Dashboard!</h1>
        <button onClick={handleLogout} className={styles.logoutButton}>
          Logout
        </button>
      </header>

      {/* ✅ Main content */}
      <main className={styles.main}>
        <ConnectPage />
      </main>
    </div>
  );
};

export const getServerSideProps: GetServerSideProps = withAuth(async (context) => {
  return { props: {} };
});

export default Home;
