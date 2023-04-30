package dev.keiji.keypair_import.sample

import android.content.pm.PackageManager
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.viewModels
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import dev.keiji.keypair_import.sample.ui.theme.AppTheme

class MainActivity : ComponentActivity() {

    private val viewModel: MainViewModel by viewModels()

    private val hasFeatureStrongBoxKeyStore: Boolean
        get() {
            return packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        setContent {
            AppTheme {
                // A surface container using the 'background' color from the theme
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    val uiState = viewModel.uiState.collectAsState().value

                    MainContent(
                        modifier = Modifier,
                        uiState = uiState,
                        onClickKeyGenerateAndImport = {
                            viewModel.generateKey(hasFeatureStrongBoxKeyStore)
                        },
                        onClickUseKey = {
                            viewModel.useKey("Hello ${System.currentTimeMillis()}")
                        }
                    )
                }
            }
        }
    }
}
