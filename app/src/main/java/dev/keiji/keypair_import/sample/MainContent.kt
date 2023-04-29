package dev.keiji.keypair_import.sample

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import dev.keiji.keypair_import.sample.ui.theme.AppTheme

@Composable
fun MainContent(
    modifier: Modifier = Modifier,
    uiState: MainViewModel.UiState = MainViewModel.UiState(),
    onClickKeyGenerateAndImport: () -> Unit = {},
    onClickUseKey: () -> Unit = {},
) {
    Column(
        modifier = modifier
            .padding(horizontal = 16.dp, vertical = 16.dp),
    ) {
        Button(
            modifier = Modifier
                .fillMaxWidth(),
            onClick = onClickKeyGenerateAndImport,
        ) {
            Text(
                text = "Generate/Import Key",
                modifier = Modifier,
            )
        }
        Button(
            modifier = Modifier
                .fillMaxWidth(),
            onClick = onClickUseKey,
        ) {
            Text(
                text = "Use Key",
                modifier = Modifier,
            )
        }

        Spacer(modifier = Modifier.padding(vertical = 8.dp))

        Text(
            text = uiState.status,
            modifier = Modifier
                .padding(horizontal = 16.dp, vertical = 8.dp),
        )
    }
}

@Preview(showBackground = true)
@Composable
fun MainContentPreview() {
    AppTheme {
        MainContent()
    }
}
